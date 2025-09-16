package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/open-policy-agent/opa/v1/rego"
)

func compileRegoPolicy(clientConfig *MCPClientConfigV2, ctx *context.Context, name string) (MiddlewareFunc, error) {
	var aclMiddleware MiddlewareFunc
	if clientConfig.Options.RegoPolicy != nil {
		compiler, err := rego.New(
			rego.Query("data.main.allow"), // The query for your policy decision
			rego.Module("main.rego", *clientConfig.Options.RegoPolicy),
		).PrepareForEval(*ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to compile policy for %s: %w", name, err)
		}
		aclMiddleware = newPolicyMiddleware(compiler)
	}

	return aclMiddleware, nil

}

// newPolicyMiddleware takes a pre-compiled policy query.
func newPolicyMiddleware(regoQuery rego.PreparedEvalQuery) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Read the request body into a buffer to allow multiple reads
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			var mcpCall map[string]interface{}
			err = json.Unmarshal(bodyBytes, &mcpCall)
			if err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}

			// LOG 1: The received JSON body
			log.Printf("Received JSON body: %s\n", string(bodyBytes))

			// Extract method
			method, ok := mcpCall["method"].(string)
			if !ok {
				http.Error(w, "Invalid MCP request: missing method", http.StatusBadRequest)
				return
			}
			// Allow tools/list and resources/list without policy check
			if method == "tools/list" || method == "resources/list" {
				next.ServeHTTP(w, r)
				return
			}
			// For other methods (e.g., tools/call), apply policy
			// Extract params
			params, ok := mcpCall["params"].(map[string]interface{})
			if !ok {
				http.Error(w, "Invalid MCP request: invalid params", http.StatusBadRequest)
				return
			}
			// Build your input for the Rego policy based on request context and params
			policyInput := make(map[string]interface{})
			for k, v := range params {
				policyInput[k] = v
			}
			policyInput["user"] = map[string]string{"role": "employee"} // Example user info; adjust as needed
			// Add other fields from the request as needed

			// LOG 2: The input sent to Rego
			inputJSON, _ := json.Marshal(policyInput)
			log.Printf("Rego policy input: %s\n", string(inputJSON))

			// Execute the Rego policy and check the result
			results, err := regoQuery.Eval(r.Context(), rego.EvalInput(policyInput))
			if err != nil {
				log.Printf("Policy evaluation error: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			// LOG 3: The evaluation result and error
			log.Printf("Rego evaluation result: %+v\n", results)

			// Check the policy decision. `results` will be empty if the policy denies access.
			if len(results) == 0 || !results[0].Expressions[0].Value.(bool) {
				http.Error(w, "Access Denied: Policy Violation", http.StatusForbidden)
				return
			}

			// If the policy check passes, continue down the middleware chain
			next.ServeHTTP(w, r)
		})
	}
}
