package cloudflare

import (
	"fmt"
	"github.com/cloudflare/cloudflare-go"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"log"
	"strings"
	"time"
)


func resourceCloudflareUserToken() *schema.Resource {
	p := schema.Resource{
		Schema: map[string]*schema.Schema{
			"resources": {
				Type:     schema.TypeList,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"permission_groups": {
				Type:     schema.TypeList,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
		},
	}

	return &schema.Resource{
		Create: resourceCloudflareUserTokenCreate,
		Read:   resourceCloudflareUserTokenRead,
		Update: resourceCloudflareUserTokenUpdate,
		Delete: resourceCloudflareUserTokenDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"value": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"status": {
				Type:      schema.TypeString,
				Computed:  true,
			},
			"issued_on": {
				Type:      schema.TypeString,
				Computed:  true,
			},
			"modified_on": {
				Type:      schema.TypeString,
				Computed:  true,
			},
			"policy": {
				Type:     schema.TypeSet,
				Required: true,
				Set:      schema.HashResource(&p),
				Elem:     &p,
			},
		},
	}
}


func resourceCloudflareUserTokenCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*cloudflare.API)

	//accountID := client.AccountID
	name := d.Get("name").(string)

	log.Printf("[INFO] Creating Cloudflare User Token: name %s", name)

	t, err := client.CreateUserToken(name, resourceDataToUserTokenPolices(d))
	if err != nil {
		return fmt.Errorf("Error creating Cloudflare User Token %q: %s", name, err)
	}

	//
	//abc, _ := json.Marshal(t)
	//
	//log.Fatal("[INFO] JSON %s", string(abc))

	d.SetId(t.ID)
	d.Set("status", t.Status)
	d.Set("issued_on", t.IssuedOn.Format(time.RFC3339Nano))
	d.Set("modified_on", t.ModifiedOn.Format(time.RFC3339Nano))
	d.Set("value", t.Value)

	return nil
}

func resourceDataToUserTokenPolices(d *schema.ResourceData) []cloudflare.UserTokenPolicy {
	schemaPolicies := d.Get("policy").(*schema.Set).List()
	policies :=  []cloudflare.UserTokenPolicy{}

	for _, p := range schemaPolicies {
		policy := p.(map[string]interface{})

		resources := expandInterfaceToStringList(policy["resources"])
		theResources := map[string]string{}
		for _, r := range resources {
			theResources[r] = "*"
		}

		permissionGroups := expandInterfaceToStringList(policy["permission_groups"])
		thePermissionGroups := []cloudflare.UserTokensPermissionGroup{}
		for _, pg := range permissionGroups {
			thePermissionGroups = append(thePermissionGroups, cloudflare.UserTokensPermissionGroup{
				ID: pg,
			})
		}

		thePolicy := cloudflare.UserTokenPolicy{
			Effect:           "allow",
			Resources:        theResources,
			PermissionGroups: thePermissionGroups,
		}

		policies = append(policies, thePolicy)
	}

	return policies
}

func resourceCloudflareUserTokenRead(d *schema.ResourceData, meta interface{}) error {

	client := meta.(*cloudflare.API)
	tokenID := d.Id()

	t, err := client.UserToken(tokenID)

	log.Printf("[DEBUG] Cloudflare UserToken: %+v", t)
	log.Printf("[DEBUG] Cloudflare UserToken error: %#v", err)

	if err != nil {
		if strings.Contains(err.Error(), "HTTP status 404") {
			log.Printf("[INFO] Cloudflare UserToken %s no longer exists", d.Id())
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Error finding Cloudflare UserToken %q: %s", d.Id(), err)
	}

	policies := []map[string]interface{}{}

	for _, p := range t.Policies {
		resources := []string{}
		for k, _ := range p.Resources {
			resources = append(resources, k)
		}

		permissionGroups := []string{}
		for _, v := range p.PermissionGroups {
			permissionGroups = append(permissionGroups, v.ID)
		}

		policies = append(policies, map[string]interface{}{
			"resources": resources,
			"permission_groups": permissionGroups,
		})
	}

	d.Set("name", t.Name)
	d.Set("policies", policies)
	d.Set("status", t.Status)
	d.Set("issued_on", t.IssuedOn.Format(time.RFC3339Nano))
	d.Set("modified_on", t.ModifiedOn.Format(time.RFC3339Nano))

	return nil
}

func resourceCloudflareUserTokenUpdate(d *schema.ResourceData, meta interface{}) error {

	client := meta.(*cloudflare.API)

	//accountID := client.AccountID
	name := d.Get("name").(string)

	t := cloudflare.UserToken{
		ID:       d.Id(),
		Name:     d.Get("name").(string),
		Policies: resourceDataToUserTokenPolices(d),
	}

	log.Printf("[INFO] Updating Cloudflare User Token: name %s", name)

	t, err := client.UpdateUserToken(t)
	if err != nil {
		return fmt.Errorf("Error updating Cloudflare User Token %q: %s", name, err)
	}

	d.Set("modified_on", t.ModifiedOn.Format(time.RFC3339Nano))

	return nil
}

func resourceCloudflareUserTokenDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*cloudflare.API)
	userTokenID := d.Id()

	log.Printf("[INFO] Deleting Cloudflare UserToken: id %s", userTokenID)

	_, err := client.DeleteUserToken(userTokenID)

	if err != nil {
		return fmt.Errorf("Error deleting Cloudflare UserToken: %s", err)
	}

	return nil
}
