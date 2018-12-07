package oke

import (
	"context"
	"strings"

	"github.com/oracle/oci-go-sdk/common"
	"github.com/oracle/oci-go-sdk/containerengine"
	"github.com/oracle/oci-go-sdk/core"
	"github.com/rancher/kontainer-engine/drivers/options"
	"github.com/rancher/kontainer-engine/types"
	"github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
	
	//"github.com/oracle/oci-go-sdk/example"
)

type Driver struct {
	driverCapabilities types.Capabilities
}
type state struct {

	v3.OracleKubernetesEngineConfig

	// Cluster Name
	Name string

	// Cluster info
	ClusterInfo types.ClusterInfo
}

func NewDriver() types.Driver {
	driver := &Driver{
		driverCapabilities: types.Capabilities{
			Capabilities: make(map[int64]bool),
		},
	}

	driver.driverCapabilities.AddCapability(types.GetVersionCapability)
	driver.driverCapabilities.AddCapability(types.SetVersionCapability)
	return driver
}

func (d *Driver) GetDriverCreateOptions(ctx context.Context) (*types.DriverFlags, error) {
	driverFlag := types.DriverFlags{
		Options: make(map[string]*types.Flag),
	}
	driverFlag.Options["tenancy-ocid"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the OCID of the tenancy",
	}
	driverFlag.Options["user-ocid"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the OCID of the user",
	}
	driverFlag.Options["region"] = &types.Flag{
		Type:  types.StringType,
		Usage: "resource region",
		value: "us-phoenix-1"
	}
	driverFlag.Options["name"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the name of the cluster that should be displayed to the user",
	}
	driverFlag.Options["cluster-compartment"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the cluster compartment in which the cluster exists",
	}
	driverFlag.Options["kubernetes-version"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The version of Kubernetes specified when creating the managed cluster",
		value: "v1.11.5",
	}
	driverFlag.Options["network-compartment"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the network compartment",
	}
	driverFlag.Options["vcn"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the name of the virtual cloud network",
	}
	driverFlag.Options["subnets"] = &types.Flag{
		Type:  types.StringSliceType,
		Usage: "comma-separated list of subnets in the virtual network to use,just support two subnets",
	}
	driverFlag.Options["service-cidr"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the CIDR block for Kubernetes services",
		value: "10.96.0.0/16",
	}
	driverFlag.Options["pods-cidr"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the CIDR block for Kubernetes pods",
		value: "10.244.0.0/16",
	}
	driverFlag.Options["nodepool-name"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the name of the node pool",
		value: "pool1",
	}
	driverFlag.Options["kubernetes-versionnode"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the version of Kubernetes running on the nodes in the node pool",
		value: "v1.11.5",
	}
	driverFlag.Options["node-image"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the image running on the nodes in the node pool",
		value: "Oracle-Linux-7.5",
	}
	driverFlag.Options["node-shape"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the node shape of the nodes in the node pool",
		value: "VM.Standard2.2",
	}
	driverFlag.Options["node-subnets"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the subnets in which to place nodes for node pool",
	}
	driverFlag.Options["quantity-persubnet"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the number of nodes in each subnet",
		value: "1",
	}
	driverFlag.Options["ssh-key"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The SSH public key to access your nodes",
	}
	driverFlag.Options["api-key"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The api key of the user",
	}
	driverFlag.Options["finger-print"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The finger print of the user",
	}
	driverFlag.Options["labels"] = &types.Flag{
		Type:  types.StringSliceType,
		Usage: "The map of Kubernetes labels (key/value pairs) to be applied to each node",
	}

	return &driverFlag, nil
}

// GetDriverUpdateOptions implements driver interface
func (d *Driver) GetDriverUpdateOptions(ctx context.Context) (*types.DriverFlags, error) {
	driverFlag := types.DriverFlags{
		Options: make(map[string]*types.Flag),
	}
	driverFlag.Options["kubernetes-version"] = &types.Flag{
		Type:  types.StringType,
		Usage: "Version of Kubernetes specified when creating the managed cluster",
		value: "v1.11.5",
	}
	driverFlag.Options["kubernetes-versionnode"] = &types.Flag{
		Type:  types.StringType,
		Usage: "version of Kubernetes running on the nodes in the node pool",
		value: "v1.11.5",
	}
	return &driverFlag, nil
}

// SetDriverOptions implements driver interface
func getStateFromOptions(driverOptions *types.DriverOptions) (state, error) {
	state := state{}
	state.TenancyID = options.GetValueFromDriverOptions(driverOptions, types.StringType, "tenancy-ocid").(string)
	state.UserID = options.GetValueFromDriverOptions(driverOptions, types.StringType, "user-ocid").(string)
	state.Region = options.GetValueFromDriverOptions(driverOptions, types.StringType, "region").(string)
	state.Name = options.GetValueFromDriverOptions(driverOptions, types.StringType, "name").(string)
	state.ClusterCompartment = options.GetValueFromDriverOptions(driverOptions, types.StringType, "cluster-compartment").(string)
	state.KubernetesVersion = options.GetValueFromDriverOptions(driverOptions, types.StringType, "kubernetes-version").(string)
	state.NetworkCompartment = options.GetValueFromDriverOptions(driverOptions, types.StringType, "network-compartment").(string)
	state.Vcn = options.GetValueFromDriverOptions(driverOptions, types.StringType, "vcn").(string)
	state.Subnets = options.GetValueFromDriverOptions(driverOptions, types.StringSliceType, "subnets").(*types.StringSlice)
	for _, Subnet := range Subnets {
		state.Subnets = append(Subnets, Subnet)
	}
	state.ServicesCidr = options.GetValueFromDriverOptions(driverOptions, types.StringType, "service-cidr").(string)
	state.PodsCidr = options.GetValueFromDriverOptions(driverOptions, types.IntType, "pods-cidr").(string)
	state.NodePoolName = options.GetValueFromDriverOptions(driverOptions, types.StringType, "nodepool-name").(string)
	state.KubernetesVersionNode = options.GetValueFromDriverOptions(driverOptions, types.StringType, "kubernetes-versionnode").(string)
	state.NodeImageName = options.GetValueFromDriverOptions(driverOptions, types.StringType, "node-image").(string)
	state.NodeShape = options.GetValueFromDriverOptions(driverOptions, types.StringType, "node-shape").(string)
	state.NodeSubnets = options.GetValueFromDriverOptions(driverOptions, types.StringType, "node-subnets").(string)
	state.QuantityPerSubnet = options.GetValueFromDriverOptions(driverOptions, types.StringType, "quantity-persubnet").(string)
	state.NodeSshKey = options.GetValueFromDriverOptions(driverOptions, types.StringType, "ssh-key").(string)
	state.ApiKey = options.GetValueFromDriverOptions(driverOptions, types.StringType, "api-key").(string)
	state.FingerPrint = options.GetValueFromDriverOptions(driverOptions, types.StringType, "finger-print").(string)
	labelValues : = options.GetValueFromDriverOptions(driverOptions, types.StringSliceType, "labels").(*types.StringSlice)
	for _, part := range labelValues.Value {
		kv := strings.Split(part, "=")
		if len(kv) == 2 {
			state.labels[kv[0]] = kv[1]
		}
	}
	return state, state.validate()
}

func (state *state) validate() error {
	if state.Name == "" {
		return fmt.Errorf("cluster name is required")
	}
	
	if state.TenancyID == "" {
		return fmt.Errorf("Tenancy ID is required")
	}
	
	if state.UserID == "" {
		return fmt.Errorf("User ID is required")
	}
	
	if state.Region == "" {
		return fmt.Errorf("Region is required")
	}

	if state.ClusterCompartmentID == "" {
		return fmt.Errorf("Cluster Compartment OCID is required")
	}
	
	if state.VCN == "" {
		return fmt.Errorf("VCN name is required")
	}

	if state.ApiKey == "" {
		return fmt.Errorf("Api key is required")
	}

	return nil
}

func getState(info *types.ClusterInfo) (state, error) {
	state := state{}

	err := json.Unmarshal([]byte(info.Metadata["state"]), &state)

	if err != nil {
		logrus.Errorf("Error encountered while marshalling state: %v", err)
	}

	return state, err
}

func (d *Driver) Create(ctx context.Context, opts *types.DriverOptions, _ *types.ClusterInfo) (*types.ClusterInfo, error) {
	
	logrus.Infof("Starting create")
	
	state, err := getStateFromOptions(options)
	if err != nil {
		return nil, fmt.Errorf("error parsing state: %v", err)
	}
	
	ctx := context.Background()
	log.Infof("tenancy: %s" + state.TenancyID)
	log.Infof("user: %s" + state.UserID)
	log.Infof("region: %s" + state.Region)
	log.Infof("tenancy: %s" + state.FingerPrint)
	log.Infof("apikey: %s" + state.ApiKey)
	provider :=common.NewRawConfigurationProvider(state.TenancyID, state.UserID, state.Region, state.FingerPrint, state.ApiKey, nil)
	
	identityClient, err := identity.NewIdentityClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("error creating identity client: %v", err)
	}

	containerEngineClient, err := containerengine.NewContainerEngineClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("error creating Container Engine client: %v", err)
	}
	
	//create vcn
	vcn := CreateOrGetVcn(ctx,provider)
	state, err := getStateFromOptions(options)
	Name := state.Name
	CompartmentId := state.ClusterCompartmentID
	VcnId := state.VcnID
	KubernetesVersion := state.KubernetesVersionmaster
	subnet1ID := state.subnet1ID
	subnet2ID := state.subnet2ID
	createClusterResp := d.createCluster(ctx, c, Name, CompartmentId, vcnID, defaulKubetVersion, subnet1ID, subnet2ID)
	req := containerengine.CreateClusterRequest{}
	req.Name = state.Name
	req.CompartmentId = state.ClusterCompartmentID
	req.VcnId = state.VcnID
	req.KubernetesVersion = state.KubernetesVersionmaster
	req.Options = &containerengine.ClusterCreateOptions{
		ServiceLbSubnetIds: {state.subnet1ID, state.subnet2ID},
	}
	resp, err := c.CreateCluster(ctx, req)
	helpers.FatalIfError(err)
	// wait until work request complete
}

func (d *Driver) Update(ctx context.Context, opts *types.DriverOptions, _ *types.ClusterInfo) (*types.ClusterInfo, error) {

	updateReq := containerengine.UpdateClusterRequest{}
	updateReq.Name = state.Name
	updateReq.ClusterId = state.ClusterCompartmentID
	updateReq.kubernetesVersion = state.KubernetesVersionmaster
	updateResp, err := c.UpdateCluster(ctx, updateReq)
	fmt.Println("updating cluster")
}





// CreateOrGetVcn either creates a new Virtual Cloud Network (VCN) or get the one already exist
func CreateOrGetVcn(ctx context.Context,provider common.ConfigurationProvider,state state) core.Vcn {
	c, err := core.NewVirtualNetworkClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("error creating VirtualNetworkClient: %v", err)
	}

	vcnItems := listVcns(ctx, c)
	
	for _, element := range vcnItems {
				if *element.DisplayName == state.Vcn {
				// VCN already created, return it
				return element
		}
	}
	

	// create a new VCN
	request := core.CreateVcnRequest{}
	if state.ServicesCidr =="" {
		request.CidrBlock = common.String("10.96.0.0/16")
	}else {
		request.CidrBlock = common.String(state.ServicesCidr)
	}
	if state.NetworkCompartment =="" {
		request.CompartmentId = common.String(state.ClusterCompartment)
	}else {
		request.CompartmentId = common.String(state.NetworkCompartment)
	}
	request.DisplayName = common.String(state.Vcn)
	request.DnsLabel = common.String("vcndns")

	r, err := c.CreateVcn(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("error creating VCN: %v", err)
	}
	return r.Vcn
}