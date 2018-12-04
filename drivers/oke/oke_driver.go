package oke
  
import (
    "strings"
    "context"
    "strings"

    "github.com/rancher/kontainer-engine/drivers/options"
    "github.com/rancher/kontainer-engine/types"
    "github.com/rancher/types/apis/management.cattle.io/v3"
    "github.com/sirupsen/logrus"
    "github.com/oracle/oci-go-sdk/common"
    "github.com/oracle/oci-go-sdk/containerengine"
    "github.com/oracle/oci-go-sdk/example/helpers"
        //"github.com/oracle/oci-go-sdk/example"
)
type Driver struct {
        driverCapabilities types.Capabilities
}
type state struct {
        // Path to the public key to use for SSH into cluster
        SSHPublicKeyPath string `json:"sshPublicKeyPath,omitempty"`

        v3.OracleKubernetesEngineConfig

        // Cluster Name
        Name string

        // The name that is displayed to the user on the Rancher UI
        DisplayName string

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
    driver.driverCapabilities.AddCapability(types.GetClusterSizeCapability)
    driver.driverCapabilities.AddCapability(types.SetClusterSizeCapability)

    return driver
}

func (d *Driver) GetDriverCreateOptions(ctx context.Context) (*types.DriverFlags, error) {
    driverFlag := types.DriverFlags{
        Options: make(map[string]*types.Flag),
    }
    driverFlag.Options["display-name"] = &types.Flag{
        Type:  types.StringType,
        Usage: "the name of the cluster that should be displayed to the user",
    }
    driverFlag.Options["compartment-id"] = &types.Flag{
    Type:  types.StringType,
    Usage: "the OCID of the compartment in which the cluster exists",
    }
    driverFlag.Options["kubernetes-version"] = &types.Flag{
    Type:  types.StringType,
    Usage: "Version of Kubernetes specified when creating the managed cluster",
    value: "v1.11.1",
    }
    driverFlag.Options["network-compartment"] = &types.Flag{
    Type:  types.StringType,
    Usage: "OCID of the network compartment",
    }
    driverFlag.Options["vcn-id"] = &types.Flag{
    Type:  types.StringType,
    Usage: "OCID of the virtual cloud network",
    }
    driverFlag.Options["subnet1ID"] = &types.Flag{
    Type:  types.StringType,
    Usage: "the first subnet used for Kubernetes services load balancers",
    }
    driverFlag.Options["subnet2ID"] = &types.Flag{
    Type:  types.StringType,
    Usage: "the second subnet used for Kubernetes services load balancers",
    }
    driverFlag.Options["pods-cidr"] = &types.Flag{
    Type:  types.StringType,
    Usage: "CIDR block for Kubernetes pods",
    }
    driverFlag.Options["service-cidr"] = &types.Flag{
    Type:  types.StringType,
    Usage: "CIDR block for Kubernetes services",
    }
    driverFlag.Options["nodepool-name"] = &types.Flag{
    Type:  types.StringType,
    Usage: "name of the node pool",
    value: "pool1",
    }
    driverFlag.Options["kubernetes-versionnode"] = &types.Flag{
    Type:  types.StringType,
    Usage: "version of Kubernetes running on the nodes in the node pool",
    value: "v1.11.1",
    }
    driverFlag.Options["node-image"] = &types.Flag{
    Type:  types.StringType,
    Usage: "name of the image running on the nodes in the node pool",
    value: "Oracle-Linux-7.5",
    }
    driverFlag.Options["node-shape"] = &types.Flag{
    Type:  types.StringType,
    Usage: "name of the node shape of the nodes in the node pool",
    value: "VM.Standard1.1",
    }
    driverFlag.Options["node-subnetid"] = &types.Flag{
    Type:  types.StringType,
    Usage: "OCIDs of the subnets in which to place nodes for node pool",
    }
    driverFlag.Options["quantity-persubnet"] = &types.Flag{
    Type:  types.StringType,
    Usage: "number of nodes in each subnet",
    value: "1",
    }
    driverFlag.Options["ssh-key"] = &types.Flag{
    Type:  types.StringType,
    Usage: "number of nodes in each subnet",
    }
    driverFlag.Options["initial-nodelabel"] = &types.Flag{
    Type:  types.StringType,
    Usage: "number of nodes in each subnet",
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
    }
    return &driverFlag, nil
}

// SetDriverOptions implements driver interface
func getStateFromOptions(driverOptions *types.DriverOptions) (state, error) {
    state := state{}
    state.Name = options.GetValueFromDriverOptions(driverOptions, types.StringType, "name").(string)
    state.DisplayName = options.GetValueFromDriverOptions(driverOptions, types.StringType, "display-name", "displayName").(string)
    state.ClusterCompartmentID = options.GetValueFromDriverOptions(driverOptions, types.StringType, "compartment-id", "compartmentId").(string)
    state.KubernetesVersionmaster = options.GetValueFromDriverOptions(driverOptions, types.StringType, "kubernetes-version", "kubernetesversionmaster").(string)
    state.NetworkCompartment = options.GetValueFromDriverOptions(driverOptions, types.IntType, "network-compartment", "networkcompartment").(string)
    state.VcnID = options.GetValueFromDriverOptions(driverOptions, types.StringType, "vcn-id", "vcnid").(string)
    state.subnet1ID = options.GetValueFromDriverOptions(driverOptions, types.StringType, "subnet1ID", "subnet1ID").(string)
    state.subnet2ID = options.GetValueFromDriverOptions(driverOptions, types.StringType, "subnet2ID", "subnet2ID").(string)
    state.PodsCidr = options.GetValueFromDriverOptions(driverOptions, types.IntType, "pods-cidr", "osDiskSizeGb").(string)
    state.ServicesCidr = options.GetValueFromDriverOptions(driverOptions, types.StringType, "service-cidr", "servicecidr").(string)
    state.NodepoolName = options.GetValueFromDriverOptions(driverOptions, types.StringType, "nodepool-name", "nodepoolname").(string)
    state.KubernetesVersionnode = options.GetValueFromDriverOptions(driverOptions, types.StringType, "kubernetes-versionnode", "kubernetesversionnode").(string)
    state.NodeImagename = options.GetValueFromDriverOptions(driverOptions, types.StringType, "node-image", "nodeimage").(string)
    state.NodeShape = options.GetValueFromDriverOptions(driverOptions, types.StringType, "node-shape", "nodeshape").(string)
    state.NodeSubnetIDs = options.GetValueFromDriverOptions(driverOptions, types.StringType, "node-subnetid", "nodesubnetid").(string)
    state.QuantityPerSubnet = options.GetValueFromDriverOptions(driverOptions, types.StringType, "quantity-persubnet", "qualitypersubnet").(string)
    state.nodesshpublickey = options.GetValueFromDriverOptions(driverOptions, types.StringType, "ssh-key", "sshkey").(string)
    state.initialNodeLabels = options.GetValueFromDriverOptions(driverOptions, types.StringType, "initial-nodelabel", "initiallabels").(string)
    for _, part := range tagValues.Value {
        kv := strings.Split(part, "=")
        if len(kv) == 2 {
            state.Tag[kv[0]] = kv[1]
        }
    }
    return state, state.validate()
}

func (state *state) validate() error {
    if state.Name == "" {
        return fmt.Errorf("cluster name is required")
    }

    if state.ClusterCompartmentID == "" {
        return fmt.Errorf("OCID of the compartment is required")
    }

    if state.VcnID == "" {
        return fmt.Errorf("OCID of the virtual cloud network is required")
    }

    if state.KubernetesVersionmaster == "" {
        return fmt.Errorf("the version of kubernetes is required")
    }

    if state.KubernetesVersionmaster == "" {
        return fmt.Errorf("the version of kubernetes is required")
    }
    if state.KubernetesVersionmaster == "" {
        return fmt.Errorf("the version of kubernetes is required")
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
    
    c, err := containerengine.NewContainerEngineClientWithConfigurationProvider(common.DefaultConfigProvider())
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