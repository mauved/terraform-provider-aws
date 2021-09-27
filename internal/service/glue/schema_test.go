package glue_test

import (
	"fmt"
	"log"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/hashicorp/aws-sdk-go-base/tfawserr"
	sdkacctest "github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	tfglue "github.com/hashicorp/terraform-provider-aws/internal/service/glue"
)

func init() {
	resource.AddTestSweepers("aws_glue_schema", &resource.Sweeper{
		Name: "aws_glue_schema",
		F:    testSweepGlueSchema,
	})
}

func testSweepGlueSchema(region string) error {
	client, err := acctest.SharedRegionalSweeperClient(region)
	if err != nil {
		return fmt.Errorf("error getting client: %s", err)
	}
	conn := client.(*conns.AWSClient).GlueConn

	listOutput, err := conn.ListSchemas(&glue.ListSchemasInput{})
	if err != nil {
		// Some endpoints that do not support Glue Schemas return InternalFailure
		if acctest.SkipSweepError(err) || tfawserr.ErrMessageContains(err, "InternalFailure", "") {
			log.Printf("[WARN] Skipping Glue Schema sweep for %s: %s", region, err)
			return nil
		}
		return fmt.Errorf("Error retrieving Glue Schema: %s", err)
	}
	for _, schema := range listOutput.Schemas {
		arn := aws.StringValue(schema.SchemaArn)
		r := tfglue.ResourceSchema()
		d := r.Data(nil)
		d.SetId(arn)

		err := r.Delete(d, client)
		if err != nil {
			log.Printf("[ERROR] Failed to delete Glue Schema %s: %s", arn, err)
		}
	}
	return nil
}

func TestAccGlueSchema_basic(t *testing.T) {
	var schema glue.GetSchemaOutput

	rName := sdkacctest.RandomWithPrefix("tf-acc-test")
	resourceName := "aws_glue_schema.test"
	registryResourceName := "aws_glue_registry.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckSchema(t) },
		ErrorCheck:   acctest.ErrorCheck(t, glue.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckSchemaDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccSchemaBasicConfig(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSchemaExists(resourceName, &schema),
					acctest.CheckResourceAttrRegionalARN(resourceName, "arn", "glue", fmt.Sprintf("schema/%s/%s", rName, rName)),
					resource.TestCheckResourceAttr(resourceName, "schema_name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", ""),
					resource.TestCheckResourceAttr(resourceName, "compatibility", "NONE"),
					resource.TestCheckResourceAttr(resourceName, "data_format", "AVRO"),
					resource.TestCheckResourceAttr(resourceName, "schema_checkpoint", "1"),
					resource.TestCheckResourceAttr(resourceName, "latest_schema_version", "1"),
					resource.TestCheckResourceAttr(resourceName, "next_schema_version", "2"),
					resource.TestCheckResourceAttr(resourceName, "schema_definition", "{\"type\": \"record\", \"name\": \"r1\", \"fields\": [ {\"name\": \"f1\", \"type\": \"int\"}, {\"name\": \"f2\", \"type\": \"string\"} ]}"),
					resource.TestCheckResourceAttrPair(resourceName, "registry_name", registryResourceName, "registry_name"),
					resource.TestCheckResourceAttrPair(resourceName, "registry_arn", registryResourceName, "arn"),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "0"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccGlueSchema_description(t *testing.T) {
	var schema glue.GetSchemaOutput

	rName := sdkacctest.RandomWithPrefix("tf-acc-test")
	resourceName := "aws_glue_schema.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckSchema(t) },
		ErrorCheck:   acctest.ErrorCheck(t, glue.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckSchemaDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccSchemaDescriptionConfig(rName, "First Description"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSchemaExists(resourceName, &schema),
					resource.TestCheckResourceAttr(resourceName, "description", "First Description"),
				),
			},
			{
				Config: testAccSchemaDescriptionConfig(rName, "Second Description"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSchemaExists(resourceName, &schema),
					resource.TestCheckResourceAttr(resourceName, "description", "Second Description"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccGlueSchema_compatibility(t *testing.T) {
	var schema glue.GetSchemaOutput

	rName := sdkacctest.RandomWithPrefix("tf-acc-test")
	resourceName := "aws_glue_schema.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckSchema(t) },
		ErrorCheck:   acctest.ErrorCheck(t, glue.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckSchemaDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccSchemaCompatibillityConfig(rName, "DISABLED"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSchemaExists(resourceName, &schema),
					resource.TestCheckResourceAttr(resourceName, "compatibility", "DISABLED"),
				),
			},
			{
				Config: testAccSchemaCompatibillityConfig(rName, "FULL"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSchemaExists(resourceName, &schema),
					resource.TestCheckResourceAttr(resourceName, "compatibility", "FULL"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccGlueSchema_tags(t *testing.T) {
	var schema glue.GetSchemaOutput
	rName := sdkacctest.RandomWithPrefix("tf-acc-test")
	resourceName := "aws_glue_schema.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckSchema(t) },
		ErrorCheck:   acctest.ErrorCheck(t, glue.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckSchemaDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccSchemaTags1Config(rName, "key1", "value1"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSchemaExists(resourceName, &schema),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "tags.key1", "value1"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccSchemaTags2Config(rName, "key1", "value1updated", "key2", "value2"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSchemaExists(resourceName, &schema),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "tags.key1", "value1updated"),
					resource.TestCheckResourceAttr(resourceName, "tags.key2", "value2"),
				),
			},
			{
				Config: testAccSchemaTags1Config(rName, "key2", "value2"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSchemaExists(resourceName, &schema),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "tags.key2", "value2"),
				),
			},
		},
	})
}

func TestAccGlueSchema_schemaDefUpdated(t *testing.T) {
	var schema glue.GetSchemaOutput

	rName := sdkacctest.RandomWithPrefix("tf-acc-test")
	resourceName := "aws_glue_schema.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckSchema(t) },
		ErrorCheck:   acctest.ErrorCheck(t, glue.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckSchemaDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccSchemaBasicConfig(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSchemaExists(resourceName, &schema),
					resource.TestCheckResourceAttr(resourceName, "schema_definition", "{\"type\": \"record\", \"name\": \"r1\", \"fields\": [ {\"name\": \"f1\", \"type\": \"int\"}, {\"name\": \"f2\", \"type\": \"string\"} ]}"),
					resource.TestCheckResourceAttr(resourceName, "latest_schema_version", "1"),
					resource.TestCheckResourceAttr(resourceName, "next_schema_version", "2"),
				),
			},
			{
				Config: testAccSchemaSchemaDefinitionUpdatedConfig(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSchemaExists(resourceName, &schema),
					resource.TestCheckResourceAttr(resourceName, "schema_definition", "{\"type\": \"record\", \"name\": \"r1\", \"fields\": [ {\"name\": \"f1\", \"type\": \"string\"}, {\"name\": \"f2\", \"type\": \"int\"} ]}"),
					resource.TestCheckResourceAttr(resourceName, "latest_schema_version", "2"),
					resource.TestCheckResourceAttr(resourceName, "next_schema_version", "3"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccGlueSchema_disappears(t *testing.T) {
	var schema glue.GetSchemaOutput

	rName := sdkacctest.RandomWithPrefix("tf-acc-test")
	resourceName := "aws_glue_schema.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckSchema(t) },
		ErrorCheck:   acctest.ErrorCheck(t, glue.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckSchemaDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccSchemaBasicConfig(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSchemaExists(resourceName, &schema),
					acctest.CheckResourceDisappears(acctest.Provider, tfglue.ResourceSchema(), resourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccGlueSchema_Disappears_registry(t *testing.T) {
	var schema glue.GetSchemaOutput

	rName := sdkacctest.RandomWithPrefix("tf-acc-test")
	resourceName := "aws_glue_schema.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckSchema(t) },
		ErrorCheck:   acctest.ErrorCheck(t, glue.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckSchemaDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccSchemaBasicConfig(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSchemaExists(resourceName, &schema),
					acctest.CheckResourceDisappears(acctest.Provider, tfglue.ResourceRegistry(), "aws_glue_registry.test"),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func testAccPreCheckSchema(t *testing.T) {
	conn := acctest.Provider.Meta().(*conns.AWSClient).GlueConn

	_, err := conn.ListRegistries(&glue.ListRegistriesInput{})

	// Some endpoints that do not support Glue Schemas return InternalFailure
	if acctest.PreCheckSkipError(err) || tfawserr.ErrMessageContains(err, "InternalFailure", "") {
		t.Skipf("skipping acceptance testing: %s", err)
	}

	if err != nil {
		t.Fatalf("unexpected PreCheck error: %s", err)
	}
}

func testAccCheckSchemaExists(resourceName string, schema *glue.GetSchemaOutput) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("Not found: %s", resourceName)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No Glue Schema ID is set")
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).GlueConn
		output, err := tfglue.FindSchemaByID(conn, rs.Primary.ID)
		if err != nil {
			return err
		}

		if output == nil {
			return fmt.Errorf("Glue Schema (%s) not found", rs.Primary.ID)
		}

		if aws.StringValue(output.SchemaArn) == rs.Primary.ID {
			*schema = *output
			return nil
		}

		return fmt.Errorf("Glue Schema (%s) not found", rs.Primary.ID)
	}
}

func testAccCheckSchemaDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aws_glue_schema" {
			continue
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).GlueConn
		output, err := tfglue.FindSchemaByID(conn, rs.Primary.ID)
		if err != nil {
			if tfawserr.ErrMessageContains(err, glue.ErrCodeEntityNotFoundException, "") {
				return nil
			}

		}

		if output != nil && aws.StringValue(output.SchemaArn) == rs.Primary.ID {
			return fmt.Errorf("Glue Schema %s still exists", rs.Primary.ID)
		}

		return err
	}

	return nil
}

func testAccSchemaBase(rName string) string {
	return fmt.Sprintf(`
resource "aws_glue_registry" "test" {
  registry_name = %[1]q
}
`, rName)
}

func testAccSchemaDescriptionConfig(rName, description string) string {
	return testAccSchemaBase(rName) + fmt.Sprintf(`
resource "aws_glue_schema" "test" {
  schema_name       = %[1]q
  registry_arn      = aws_glue_registry.test.arn
  data_format       = "AVRO"
  compatibility     = "NONE"
  description       = %[2]q
  schema_definition = "{\"type\": \"record\", \"name\": \"r1\", \"fields\": [ {\"name\": \"f1\", \"type\": \"int\"}, {\"name\": \"f2\", \"type\": \"string\"} ]}"
}
`, rName, description)
}

func testAccSchemaCompatibillityConfig(rName, compat string) string {
	return testAccSchemaBase(rName) + fmt.Sprintf(`
resource "aws_glue_schema" "test" {
  schema_name       = %[1]q
  registry_arn      = aws_glue_registry.test.arn
  data_format       = "AVRO"
  compatibility     = %[2]q
  schema_definition = "{\"type\": \"record\", \"name\": \"r1\", \"fields\": [ {\"name\": \"f1\", \"type\": \"int\"}, {\"name\": \"f2\", \"type\": \"string\"} ]}"
}
`, rName, compat)
}

func testAccSchemaBasicConfig(rName string) string {
	return testAccSchemaBase(rName) + fmt.Sprintf(`
resource "aws_glue_schema" "test" {
  schema_name       = %[1]q
  registry_arn      = aws_glue_registry.test.arn
  data_format       = "AVRO"
  compatibility     = "NONE"
  schema_definition = "{\"type\": \"record\", \"name\": \"r1\", \"fields\": [ {\"name\": \"f1\", \"type\": \"int\"}, {\"name\": \"f2\", \"type\": \"string\"} ]}"
}
`, rName)
}

func testAccSchemaTags1Config(rName, tagKey1, tagValue1 string) string {
	return testAccSchemaBase(rName) + fmt.Sprintf(`
resource "aws_glue_schema" "test" {
  schema_name       = %[1]q
  registry_arn      = aws_glue_registry.test.arn
  data_format       = "AVRO"
  compatibility     = "NONE"
  schema_definition = "{\"type\": \"record\", \"name\": \"r1\", \"fields\": [ {\"name\": \"f1\", \"type\": \"int\"}, {\"name\": \"f2\", \"type\": \"string\"} ]}"

  tags = {
    %[2]q = %[3]q
  }
}
`, rName, tagKey1, tagValue1)
}

func testAccSchemaTags2Config(rName, tagKey1, tagValue1, tagKey2, tagValue2 string) string {
	return testAccSchemaBase(rName) + fmt.Sprintf(`
resource "aws_glue_schema" "test" {
  schema_name       = %[1]q
  registry_arn      = aws_glue_registry.test.arn
  data_format       = "AVRO"
  compatibility     = "NONE"
  schema_definition = "{\"type\": \"record\", \"name\": \"r1\", \"fields\": [ {\"name\": \"f1\", \"type\": \"int\"}, {\"name\": \"f2\", \"type\": \"string\"} ]}"

  tags = {
    %[2]q = %[3]q
    %[4]q = %[5]q
  }
}
`, rName, tagKey1, tagValue1, tagKey2, tagValue2)
}

func testAccSchemaSchemaDefinitionUpdatedConfig(rName string) string {
	return testAccSchemaBase(rName) + fmt.Sprintf(`
resource "aws_glue_schema" "test" {
  schema_name       = %[1]q
  registry_arn      = aws_glue_registry.test.arn
  data_format       = "AVRO"
  compatibility     = "NONE"
  schema_definition = "{\"type\": \"record\", \"name\": \"r1\", \"fields\": [ {\"name\": \"f1\", \"type\": \"string\"}, {\"name\": \"f2\", \"type\": \"int\"} ]}"
}
`, rName)
}
