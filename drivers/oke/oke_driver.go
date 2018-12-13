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
		value: "us-phoenix-1",
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
	labelValues := options.GetValueFromDriverOptions(driverOptions, types.StringSliceType, "labels").(*types.StringSlice)
	for _, part := range labelValues.Value {
		kv := strings.Split(part, "=")
		if len(kv) == 2 {
			state.Labels[kv[0]] = kv[1]
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
	logrus.Infof("tenancy: %s", state.TenancyID)
	logrus.Infof("user: %s", state.UserID)
	logrus.Infof("region: %s", state.Region)
	logrus.Infof("tenancy: %s", state.FingerPrint)
	logrus.Infof("apikey: %s", state.ApiKey)
	provider := common.NewRawConfigurationProvider(state.TenancyID, state.UserID, state.Region, state.FingerPrint, state.ApiKey, nil)

	identityClient, err := identity.NewIdentityClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("error creating identity client: %v", err)
	}

	containerEngineClient, err := containerengine.NewContainerEngineClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("error creating Container Engine client: %v", err)
	}

	request := identity.ListAvailabilityDomainsRequest{
		CompartmentId: &tenancyID,
	}

	ads, err := c.ListAvailabilityDomains(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("error listing available domain: %v", err)
	}

	logrus.Infof("List of available domains: %v", ads.Items)

	//create vcn
	vcn, err := CreateOrGetVcn(ctx, provider, state)
	if err != nil {
		return nil, fmt.Errorf("error creating vcn: %v", err)
	}

	name := state.Name
	if state.NetworkCompartment == "" {
		compartmentId = common.String(state.ClusterCompartment)
	} else {
		compartmentId = common.String(state.NetworkCompartment)
	}
	vcnID := vcn.Id
	kubernetesVersion := state.KubernetesVersion
	subnets := state.Subnets
	subnet1CIDR := common.String("10.0.0.0/24")
	dnsLabel1 := common.String("subnetdns1")
	subnet1 := CreateOrGetSubnetWithDetails(ctx, provider, compartmentId, common.String(subnets[0]), subnet1CIDR, dnsLabel1, ads.Items[0].Name)
	logrus.Infof("create subnet1 complete")
	logrus.Infof("subnet1:", subnet1)

	subnet2CIDR := common.String("10.0.1.0/24")
	dnsLabel2 := common.String("subnetdns2")
	subnet2 := CreateOrGetSubnetWithDetails(ctx, provider, compartmentId, common.String(subnets[1]), subnet2CIDR, dnsLabel2, ads.Items[1].Name)
	logrus.Infof("create subnet2 complete")
	logrus.Infof("subnet2:", subnet2)

	subnet3CIDR := common.String("10.0.2.0/24")
	dnsLabel2 := common.String("subnetdns3")
	subnet3 := CreateOrGetSubnetWithDetails(ctx, provider, compartmentId, common.String(subnets[1]), subnet3CIDR, dnsLabel3, ads.Items[2].Name)
	logrus.Infof("create subnet3 complete")
	logrus.Infof("subnet2:", subnet2)

	logrus.Infof("creating cluster")
	createClusterResp := createCluster(ctx, containerEngineClient, state.ClusterCompartment, *vcn.Id, kubernetesVersion, *subnet1.Id, *subnet2.Id)

	// wait until work request complete
	workReqResp := waitUntilWorkRequestComplete(c, createClusterResp.OpcWorkRequestId)
	logrus.Infof("cluster created")
	clusterID := getResourceID(workReqResp.Resources, containerengine.WorkRequestResourceActionTypeCreated, "CLUSTER")

	// create NodePool
	createNodePoolReq := containerengine.CreateNodePoolRequest{}
	createNodePoolReq.CompartmentId = common.String(state.ClusterCompartment)
	createNodePoolReq.Name = common.String(state.Name)
	createNodePoolReq.ClusterId = common.String(clusterID)
	createNodePoolReq.KubernetesVersion = common.String(state.KubernetesVersionNode)
	createNodePoolReq.NodeImageName = common.String(state.NodeImageName)
	createNodePoolReq.NodeShape = common.String(state.NodeShape)
	createNodePoolReq.SubnetIds = []string{subnet3.Id}
	createNodePoolReq.InitialNodeLabels = []containerengine.KeyValue{}
	for key, value := range state.Labels {
		tmpKey := key
		tmpValue := value
		keyValue := containerengine.KeyValue{Key: &tmpKey, Value: &tmpValue}
		createNodePoolReq.InitialNodeLabels = append(label, keyValue)
	}

	createNodePoolResp, err := c.CreateNodePool(ctx, createNodePoolReq)
	if err != nil {
		return nil, fmt.Errorf("error creating node pool: %v", err)
	}
	logrus.Infof("creating nodepool")

	workReqResp = waitUntilWorkRequestComplete(c, createNodePoolResp.OpcWorkRequestId)
	logrus.Infof("nodepool created")

	info := &types.ClusterInfo{}
	return info, storeState(info, state)
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
func CreateOrGetVcn(ctx context.Context, provider common.ConfigurationProvider, state state) (core.Vcn, error) {
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
	if state.ServicesCidr == "" {
		request.CidrBlock = common.String("10.96.0.0/16")
	} else {
		request.CidrBlock = common.String(state.ServicesCidr)
	}
	if state.NetworkCompartment == "" {
		request.CompartmentId = common.String(state.ClusterCompartment)
	} else {
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

// CreateOrGetSubnetWithDetails either creates a new Virtual Cloud Network (VCN) or get the one already exist
// with detail info
func CreateOrGetSubnetWithDetails(ctx context.Context, provider common.ConfigurationProvider, compartmentId string, vcnID string, displayName *string, cidrBlock *string, dnsLabel *string, availableDomain *string) (core.Subnet, error) {
	c, err := core.NewVirtualNetworkClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("error creating virtual network client: %v", err)
	}

	subnets := listSubnets(ctx, c, provider)

	// check if the subnet has already been created
	for _, element := range subnets {
		if *element.DisplayName == *displayName {
			// find the subnet, return it
			return element
		}
	}

	// create a new subnet
	request := core.CreateSubnetRequest{}
	request.AvailabilityDomain = availableDomain
	request.CompartmentId = common.String(compartmentId)
	request.CidrBlock = cidrBlock
	request.DisplayName = displayName
	request.DnsLabel = dnsLabel
	request.RequestMetadata = GetRequestMetadataWithDefaultRetryPolicy()
	request.VcnId = vcnID

	r, err := c.CreateSubnet(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("error creating subnet: %v", err)
	}

	// retry condition check, stop unitl return true
	pollUntilAvailable := func(r common.OCIOperationResponse) bool {
		if converted, ok := r.Response.(core.GetSubnetResponse); ok {
			return converted.LifecycleState != core.SubnetLifecycleStateAvailable
		}
		return true
	}

	pollGetRequest := core.GetSubnetRequest{
		SubnetId:        r.Id,
		RequestMetadata: GetRequestMetadataWithCustomizedRetryPolicy(pollUntilAvailable),
	}

	// wait for lifecyle become running
	_, pollErr := c.GetSubnet(ctx, pollGetRequest)
	if pollErr != nil {
		return nil, fmt.Errorf("error creating subnet: %v", err)
	}

	// update the security rules
	getReq := core.GetSecurityListRequest{
		SecurityListId: common.String(r.SecurityListIds[0]),
	}

	getResp, err := c.GetSecurityList(ctx, getReq)
	if err != nil {
		return nil, fmt.Errorf("error creating subnet: %v", err)
	}

	// this security rule allows remote control the instance
	portRange := core.PortRange{
		Max: common.Int(1521),
		Min: common.Int(1521),
	}

	newRules := append(getResp.IngressSecurityRules, core.IngressSecurityRule{
		Protocol: common.String("6"), // TCP
		Source:   common.String("0.0.0.0/0"),
		TcpOptions: &core.TcpOptions{
			DestinationPortRange: &portRange,
		},
	})

	updateReq := core.UpdateSecurityListRequest{
		SecurityListId: common.String(r.SecurityListIds[0]),
	}

	updateReq.IngressSecurityRules = newRules

	_, err = c.UpdateSecurityList(ctx, updateReq)
	if err != nil {
		return nil, fmt.Errorf("error creating subnet: %v", err)
	}

	return r.Subnet
}

// create a cluster
func createCluster(
	ctx context.Context,
	client containerengine.ContainerEngineClient,
	name, compartmentId, vcnID, kubernetesVersion, subnet1ID, subnet2ID string) (containerengine.CreateClusterResponse, error) {
	req := containerengine.CreateClusterRequest{}
	req.Name = common.String(name)
	req.CompartmentId = common.String(compartmentId)
	req.VcnId = common.String(vcnID)
	req.KubernetesVersion = common.String(kubernetesVersion)
	req.Options = &containerengine.ClusterCreateOptions{
		ServiceLbSubnetIds: []string{subnet1ID, subnet2ID},
	}

	resp, err := client.CreateCluster(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("error creating cluster: %v", err)
	}

	return resp, nil
}

func GetRequestMetadataWithDefaultRetryPolicy() common.RequestMetadata {
	return common.RequestMetadata{
		RetryPolicy: getDefaultRetryPolicy(),
	}
}

func GetRequestMetadataWithCustomizedRetryPolicy(fn func(r common.OCIOperationResponse) bool) common.RequestMetadata {
	return common.RequestMetadata{
		RetryPolicy: getExponentialBackoffRetryPolicy(uint(20), fn),
	}
}

func getDefaultRetryPolicy() *common.RetryPolicy {
	// how many times to do the retry
	attempts := uint(10)

	// retry for all non-200 status code
	retryOnAllNon200ResponseCodes := func(r common.OCIOperationResponse) bool {
		return !(r.Error == nil && 199 < r.Response.HTTPResponse().StatusCode && r.Response.HTTPResponse().StatusCode < 300)
	}
	return getExponentialBackoffRetryPolicy(attempts, retryOnAllNon200ResponseCodes)
}

func getExponentialBackoffRetryPolicy(n uint, fn func(r common.OCIOperationResponse) bool) *common.RetryPolicy {
	// the duration between each retry operation, you might want to waite longer each time the retry fails
	exponentialBackoff := func(r common.OCIOperationResponse) time.Duration {
		return time.Duration(math.Pow(float64(2), float64(r.AttemptNumber-1))) * time.Second
	}
	policy := common.NewRetryPolicy(n, fn, exponentialBackoff)
	return &policy
}

// wait until work request finish
func waitUntilWorkRequestComplete(client containerengine.ContainerEngineClient, workReuqestID *string) (containerengine.GetWorkRequestResponse, error) {
	// retry GetWorkRequest call until TimeFinished is set
	shouldRetryFunc := func(r common.OCIOperationResponse) bool {
		return r.Response.(containerengine.GetWorkRequestResponse).TimeFinished == nil
	}

	getWorkReq := containerengine.GetWorkRequestRequest{
		WorkRequestId:   workReuqestID,
		RequestMetadata: helpers.GetRequestMetadataWithCustomizedRetryPolicy(shouldRetryFunc),
	}

	getResp, err := client.GetWorkRequest(context.Background(), getWorkReq)
	if err != nil {
		return nil, fmt.Errorf("error waiting work request complete: %v", err)
	}
	return getResp, nil
}
