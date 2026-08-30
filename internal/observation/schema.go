/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package observation

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"trawl.cloud/trawl/internal/sanitize"
)

// schemaJSON is the normative envelope schema, embedded so the binary validates
// against the same document the contract publishes.
//
// Embedding rather than reading from disk matters: a sensor pod has no access to
// the repository, and a schema loaded from a ConfigMap could drift from the code
// that produces the records. A contract test asserts the embedded copy matches
// contracts/observation.schema.json.
//
//go:embed observation.schema.json
var schemaJSON []byte

// SchemaJSON returns the embedded normative schema.
func SchemaJSON() []byte {
	out := make([]byte, len(schemaJSON))
	copy(out, schemaJSON)
	return out
}

var (
	compiledOnce sync.Once
	compiled     *jsonschema.Schema
	errCompile   error
)

// Schema returns the compiled envelope schema.
func Schema() (*jsonschema.Schema, error) {
	compiledOnce.Do(func() {
		var doc any
		if err := json.Unmarshal(schemaJSON, &doc); err != nil {
			errCompile = sanitize.Errorf("parsing embedded observation schema: %v", err)
			return
		}
		c := jsonschema.NewCompiler()
		const url = "https://trawl.cloud/schemas/observation/v1alpha1.json"
		if err := c.AddResource(url, doc); err != nil {
			errCompile = sanitize.Errorf("registering observation schema: %v", err)
			return
		}
		compiled, errCompile = c.Compile(url)
	})
	return compiled, errCompile
}

// Validate checks a record against the normative schema.
//
// The sensor validates every record it emits, not just in tests. Loki has no
// schema enforcement, so an invalid record would be stored and only discovered
// when a dashboard query silently returned nothing. Failing at the sensor turns
// that into a counted rejection with a diagnostic fingerprint (FR-016).
func Validate(obs *Observation) error {
	schema, err := Schema()
	if err != nil {
		return err
	}

	encoded, err := json.Marshal(obs)
	if err != nil {
		return sanitize.Errorf("encoding observation: %v", err)
	}
	var doc any
	if err := json.Unmarshal(encoded, &doc); err != nil {
		return sanitize.Errorf("re-decoding observation: %v", err)
	}

	if err := schema.Validate(doc); err != nil {
		// A validation error quotes the offending instance, which for a
		// malformed analyzer record can include traffic content. Only the
		// structural location is kept.
		return fmt.Errorf("observation does not satisfy %s: %s",
			SchemaVersion, schemaLocations(err))
	}
	return nil
}

// schemaLocations reduces a validation error to the failing keyword paths,
// dropping the instance values it would otherwise quote.
func schemaLocations(err error) string {
	// errors.As, not a type assertion: the error may be wrapped by the time it
	// reaches here, and a failed assertion would silently discard the location
	// detail that makes a rejection diagnosable.
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return "validation failed"
	}

	var locations []string
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		loc := e.InstanceLocation
		if len(loc) > 0 {
			locations = append(locations, "/"+strings.Join(loc, "/"))
		}
		for _, cause := range e.Causes {
			walk(cause)
		}
	}
	walk(ve)

	if len(locations) == 0 {
		return "validation failed at the document root"
	}
	if len(locations) > 8 {
		locations = locations[:8]
	}
	return strings.Join(locations, ", ")
}

// Normalize fills in the envelope fields every record must carry and checks the
// internal consistency the schema cannot express.
func Normalize(obs *Observation) error {
	obs.SchemaVersion = SchemaVersion

	inferred, exactlyOne := obs.Details.TypeOf()
	if !exactlyOne {
		// Zero bodies is an envelope with no observation in it; two is a record
		// that is ambiguous about what it describes.
		return fmt.Errorf("observation details must contain exactly one subtype body")
	}
	if obs.ObservationType == "" {
		obs.ObservationType = inferred
	}
	if obs.ObservationType != inferred {
		return fmt.Errorf("observation_type %q does not match the %q details body",
			obs.ObservationType, inferred)
	}

	// A zero time marshals to 0001-01-01T00:00:00Z, which is a syntactically
	// valid date-time, so the schema accepts it. The record would then sit in
	// Loki dated year 1: invisible to every dashboard range query, and
	// impossible to place in a timeline. JSON Schema cannot express "a
	// plausible timestamp", so it is checked here.
	if obs.EventTime.IsZero() {
		return errors.New("observation has no event time")
	}
	if obs.ObservedAt.IsZero() {
		return errors.New("observation has no observation time")
	}

	return nil
}
