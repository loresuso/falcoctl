package index

import (
	"bytes"
	"encoding/json"
	"github.com/invopop/jsonschema"
)

func GenerateSchema() {
	reflector := jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true,  // all properties are optional by default
		AllowAdditionalProperties:  false, // unrecognized properties don't cause a parsing failures
	}
	schema, _ := reflector.Reflect(&PluginIndex{}).MarshalJSON()
	var prettyJSON bytes.Buffer
	json.Indent(&prettyJSON, schema, "", "\t")
	println(string(prettyJSON.Bytes()))
}

func ValidateSchema() {

}