package ssm

import (
	"fmt"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/flex"
)

func DataSourcePatchBaseline() *schema.Resource {
	return &schema.Resource{
		Read: dataPatchBaselineRead,
		Schema: map[string]*schema.Schema{
			"owner": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringLenBetween(1, 255),
			},
			"name_prefix": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringLenBetween(0, 255),
			},
			"default_baseline": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"operating_system": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice(ssm.OperatingSystem_Values(), false),
			},
			// Computed values
			"description": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"name": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func dataPatchBaselineRead(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*conns.AWSClient).SSMConn

	filters := []*ssm.PatchOrchestratorFilter{
		{
			Key: aws.String("OWNER"),
			Values: []*string{
				aws.String(d.Get("owner").(string)),
			},
		},
	}

	if v, ok := d.GetOk("name_prefix"); ok {
		filters = append(filters, &ssm.PatchOrchestratorFilter{
			Key: aws.String("NAME_PREFIX"),
			Values: []*string{
				aws.String(v.(string)),
			},
		})
	}

	params := &ssm.DescribePatchBaselinesInput{
		Filters: filters,
	}

	log.Printf("[DEBUG] Reading DescribePatchBaselines: %s", params)

	resp, err := conn.DescribePatchBaselines(params)

	if err != nil {
		return fmt.Errorf("Error describing SSM PatchBaselines: %w", err)
	}

	var filteredBaselines []*ssm.PatchBaselineIdentity
	if v, ok := d.GetOk("operating_system"); ok {
		for _, baseline := range resp.BaselineIdentities {
			if v.(string) == aws.StringValue(baseline.OperatingSystem) {
				filteredBaselines = append(filteredBaselines, baseline)
			}
		}
	}

	if v, ok := d.GetOk("default_baseline"); ok {
		for _, baseline := range filteredBaselines {
			if v.(bool) == aws.BoolValue(baseline.DefaultBaseline) {
				filteredBaselines = []*ssm.PatchBaselineIdentity{baseline}
				break
			}
		}
	}

	if len(filteredBaselines) < 1 || filteredBaselines[0] == nil {
		return fmt.Errorf("Your query returned no results. Please change your search criteria and try again.")
	}

	if len(filteredBaselines) > 1 {
		return fmt.Errorf("Your query returned more than one result. Please try a more specific search criteria")
	}

	baseline, err := conn.GetPatchBaseline(&ssm.GetPatchBaselineInput{
		BaselineId: filteredBaselines[0].BaselineId,
	})

	if err != nil {
		return fmt.Errorf("Error getting SSM PatchBaseline: %w", err)
	}

	d.SetId(aws.StringValue(baseline.BaselineId))
	d.Set("name", baseline.Name)
	d.Set("description", baseline.Description)
	d.Set("default_baseline", filteredBaselines[0].DefaultBaseline)
	d.Set("operating_system", baseline.OperatingSystem)
	d.Set("approved_patches_compliance_level", baseline.ApprovedPatchesComplianceLevel)
	d.Set("approved_patches", flex.FlattenStringList(baseline.ApprovedPatches))
	d.Set("rejected_patches", flex.FlattenStringList(baseline.RejectedPatches))
	d.Set("rejected_patches_action", baseline.RejectedPatchesAction)
	d.Set("approved_patches_enable_non_security", baseline.ApprovedPatchesEnableNonSecurity)

	if err := d.Set("global_filter", flattenPatchFilterGroup(baseline.GlobalFilters)); err != nil {
		return fmt.Errorf("Error setting global filters error: %#v", err)
	}

	if err := d.Set("approval_rule", flattenPatchRuleGroup(baseline.ApprovalRules)); err != nil {
		return fmt.Errorf("Error setting approval rules error: %#v", err)
	}

	if err := d.Set("source", flattenPatchSource(baseline.Sources)); err != nil {
		return fmt.Errorf("Error setting patch sources error: %#v", err)
	}

	arn := arn.ARN{
		Partition: meta.(*conns.AWSClient).Partition,
		Region:    meta.(*conns.AWSClient).Region,
		Service:   "ssm",
		AccountID: meta.(*conns.AWSClient).AccountID,
		Resource:  fmt.Sprintf("patchbaseline/%s", strings.TrimPrefix(d.Id(), "/")),
	}
	d.Set("arn", arn.String())

	return nil
}
