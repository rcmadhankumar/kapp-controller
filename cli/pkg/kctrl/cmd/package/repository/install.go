package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/cppforlife/go-cli-ui/ui"
	"github.com/spf13/cobra"
	cmdapp "github.com/vmware-tanzu/carvel-kapp-controller/cli/pkg/kctrl/cmd/app"
	cmdcore "github.com/vmware-tanzu/carvel-kapp-controller/cli/pkg/kctrl/cmd/core"
	ins "github.com/vmware-tanzu/carvel-kapp-controller/cli/pkg/kctrl/cmd/package/installed"
	cmdlocal "github.com/vmware-tanzu/carvel-kapp-controller/cli/pkg/kctrl/local"
	lclcfg "github.com/vmware-tanzu/carvel-kapp-controller/cli/pkg/kctrl/local"
	"github.com/vmware-tanzu/carvel-kapp-controller/cli/pkg/kctrl/logger"
	kcv1alpha1 "github.com/vmware-tanzu/carvel-kapp-controller/pkg/apis/kappctrl/v1alpha1"
	kcpkgv1alpha1 "github.com/vmware-tanzu/carvel-kapp-controller/pkg/apis/packaging/v1alpha1"
	pkgv1alpha1 "github.com/vmware-tanzu/carvel-kapp-controller/pkg/apis/packaging/v1alpha1"
	fakekc "github.com/vmware-tanzu/carvel-kapp-controller/pkg/client/clientset/versioned/fake"
	versions "github.com/vmware-tanzu/carvel-vendir/pkg/vendir/versions/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

type InstallPackageOptions struct {
	ui          ui.UI
	statusUI    cmdcore.StatusLoggingUI
	depsFactory cmdcore.DepsFactory
	logger      logger.Logger

	repoURL            string
	packageName        string
	version            string
	valuesFile         string
	values             bool
	serviceAccountName string
	install            bool

	Name                 string
	NamespaceFlags       cmdcore.NamespaceFlags
	SecureNamespaceFlags cmdcore.SecureNamespaceFlags
	createdAnnotations   *(ins.CreatedResourceAnnotations)
	pkgCmdTreeOpts       cmdcore.PackageCommandTreeOpts

	Local     bool
	KbldBuild bool
	Delete    bool
	Debug     bool
}

func NewInstallPackageOptions(ui ui.UI, depsFactory cmdcore.DepsFactory, logger logger.Logger, pkgCmdTreeOpts cmdcore.PackageCommandTreeOpts) *InstallPackageOptions {
	return &InstallPackageOptions{ui: ui, statusUI: cmdcore.NewStatusLoggingUI(ui), depsFactory: depsFactory, logger: logger, pkgCmdTreeOpts: pkgCmdTreeOpts}
}

func NewInstallPackageCmd(o *InstallPackageOptions, flagsFactory cmdcore.FlagsFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "install",
		Aliases: []string{"lp", "ls-p"},
		Short:   "Install a package from a package repository from the given package repository URL",
		RunE:    func(_ *cobra.Command, _ []string) error { return o.Run() },
		Example: cmdcore.Examples{
			cmdcore.Example{"Install package from a package repository",
				[]string{"package", "repository", "install", "--url", "index.docker.io/sample-registry/package-repo:1.0.0", "-p", "package.corp.com", "--version", "1.0.0"},
			},
			cmdcore.Example{"Instaall package from a package repository with values file",
				[]string{"package", "repository", "install", "--url", "index.docker.io/sample-registry/package-repo:1.0.0", "-p", "package.corp.com", "--version", "1.0.0", "--values-file", "values.yml"},
			},
			cmdcore.Example{"Install package from a package repository with values file",
				[]string{"package", "repository", "install", "--url", "index.docker.io/sample-registry/package-repo:1.0.0", "-p", "package.corp.com", "--version", "1.0.0", "--service-account-name", "existing-sa"},
			},
		}.Description("", o.pkgCmdTreeOpts),
		SilenceUsage: true,
		Annotations: map[string]string{"table": "",
			cmdcore.PackageManagementCommandsHelpGroup.Key: cmdcore.PackageManagementCommandsHelpGroup.Value},
	}

	o.NamespaceFlags.SetWithPackageCommandTreeOpts(cmd, flagsFactory, o.pkgCmdTreeOpts)
	o.SecureNamespaceFlags.Set(cmd)

	cmd.Flags().StringVarP(&o.Name, "install-name", "i", "", "Set package name (required)")
	cmd.Flags().StringVarP(&o.packageName, "package", "p", "", "Set package name (required)")
	cmd.Flags().StringVarP(&o.repoURL, "url", "u", "", "Set package name (required)")
	cmd.Flags().StringVarP(&o.version, "version", "v", "", "Set package version (required)")
	cmd.Flags().StringVar(&o.serviceAccountName, "service-account-name", "", "Name of an existing service account used to install underlying package contents, optional")
	cmd.Flags().StringVar(&o.valuesFile, "values-file", "", "The path to the configuration values file, optional")
	cmd.Flags().BoolVar(&o.values, "values", true, "Add or keep values supplied to package install, optional")

	cmd.Flags().BoolVarP(&o.Local, "local", "l", false, "Use local fetch source")
	cmd.Flags().BoolVarP(&o.KbldBuild, "kbld-build", "b", false, "Allow kbld build")
	cmd.Flags().BoolVar(&o.Delete, "delete", false, "Delete deployed app")
	cmd.Flags().BoolVar(&o.Debug, "debug", true, "Show kapp-controller logs")

	return cmd
}

func (o *InstallPackageOptions) Run() error {
	if len(o.packageName) == 0 {
		return fmt.Errorf("Expected package name to be non empty")
	}

	if len(o.repoURL) == 0 {
		return fmt.Errorf("Expected package repository url to be non-empty")
	}

	if len(o.version) == 0 {
		return fmt.Errorf("Expected package version to be non empty")
	}

	o.createdAnnotations = ins.NewCreatedResourceAnnotations(o.Name, o.NamespaceFlags.Name)
	svcAccount := o.serviceAccountName
	if svcAccount == "" {
		svcAccount = o.createdAnnotations.ServiceAccountAnnValue()
	}

	client, err := o.depsFactory.CoreClient()
	if err != nil {
		return err
	}
	return o.create(client)
}

func (o *InstallPackageOptions) create(client kubernetes.Interface) error {
	isServiceAccountCreated, isSecretCreated, err := o.createRelatedResources(client)
	if err != nil {
		return err
	}

	o.ui.PrintLinef("Creating package install resource")
	packageInstall, err := o.createPackageInstall(isServiceAccountCreated, isSecretCreated)
	if err != nil {
		return err
	}

	fmt.Printf("\n ====> package Install: %+v", packageInstall)

	marshaled2, err := json.MarshalIndent(packageInstall, "", "   ")
	if err != nil {
		fmt.Printf("marshaling error: %s", err)
	}
	fmt.Println("\n\n\n\n\n ----- Pkg Install generated :  ------ \n\n\n")
	fmt.Printf(string(marshaled2))
	fmt.Println("\n\n\n\n\n ----- ----- ----- ----- ----- \n\n\n\n\n")

	configs, err := loadImgpkgBundleToConfigs(o.ui, o.repoURL)
	if err != nil {
		return err
	}

	err = o.changePackageNamespace(&configs)
	if err != nil {
		return err
	}

	marshaled2, err = json.MarshalIndent(configs, "", "   ")
	if err != nil {
		fmt.Printf("marshaling error: %s", err)
	}
	fmt.Println("\n\n\n\n\n ----- configs :  ------ \n\n\n")
	fmt.Printf(string(marshaled2))
	fmt.Println("\n\n\n\n\n ----- ----- ----- ----- ----- \n\n\n\n\n")

	configs.PkgInstalls = []pkgv1alpha1.PackageInstall{*packageInstall}

	marshaled2, err = json.MarshalIndent(configs, "", "   ")
	if err != nil {
		fmt.Printf("marshaling error: %s", err)
	}
	fmt.Println("\n\n\n\n\n ----- configs after package install added :  ------ \n\n\n")
	fmt.Printf(string(marshaled2))
	fmt.Println("\n\n\n\n\n ----- ----- ----- ----- ----- \n\n\n\n\n")

	cmdRunner := cmdlocal.NewDetailedCmdRunner(os.Stdout, o.Debug)
	reconciler := cmdlocal.NewReconciler(o.depsFactory, cmdRunner, o.logger)

	reconcileErr := reconciler.Reconcile(configs, cmdlocal.ReconcileOpts{
		Local:           o.Local,
		KbldBuild:       o.KbldBuild,
		Delete:          o.Delete,
		Debug:           o.Debug,
		DeployResources: true,

		BeforeAppReconcile: o.beforeAppReconcile,
		AfterAppReconcile:  o.afterAppReconcile,
	})

	// TODO app watcher needs a little time to run; should block ideally
	time.Sleep(100 * time.Millisecond)

	return reconcileErr
}

func (o *InstallPackageOptions) beforeAppReconcile(app kcv1alpha1.App, kcClient *fakekc.Clientset) error {
	err := o.printRs(app.ObjectMeta, kcClient)
	if err != nil {
		return err
	}

	o.ui.PrintLinef("Reconciling in-memory app/%s (namespace: %s) ...", app.Name, app.Namespace)

	go func() {
		appWatcher := cmdapp.NewAppTailer(app.Namespace, app.Name,
			o.ui, kcClient, cmdapp.AppTailerOpts{IgnoreNotExists: true})

		err := appWatcher.TailAppStatus()
		if err != nil {
			o.ui.PrintLinef("App tailing error: %s", err)
		}
	}()

	return nil
}

func (o *InstallPackageOptions) afterAppReconcile(app kcv1alpha1.App, kcClient *fakekc.Clientset) error {
	if o.Debug {
		return o.printRs(app.ObjectMeta, kcClient)
	}
	return nil
}

func (o *InstallPackageOptions) printRs(nsName metav1.ObjectMeta, kcClient *fakekc.Clientset) error {
	app, err := kcClient.KappctrlV1alpha1().Apps(nsName.Namespace).Get(context.Background(), nsName.Name, metav1.GetOptions{})
	if err == nil {
		bs, err := yaml.Marshal(app)
		if err != nil {
			return fmt.Errorf("Marshaling App CR: %s", err)
		}

		o.ui.PrintBlock(bs)
	}

	pkgi, err := kcClient.PackagingV1alpha1().PackageInstalls(nsName.Namespace).Get(context.Background(), nsName.Name, metav1.GetOptions{})
	if err == nil {
		bs, err := yaml.Marshal(pkgi)
		if err != nil {
			return fmt.Errorf("Marshaling PackageInstall CR: %s", err)
		}

		o.ui.PrintBlock(bs)
	}

	return nil
}

func (o *InstallPackageOptions) createRelatedResources(client kubernetes.Interface) (bool, bool, error) {
	fmt.Printf("\n ====> createRelatedResources ")
	var (
		isServiceAccountCreated bool
		isSecretCreated         bool
		err                     error
	)

	if o.serviceAccountName == "" {

		fmt.Println(o.createdAnnotations.ServiceAccountAnnValue())
		fmt.Printf("here- creating service account")
		o.statusUI.PrintMessagef("Creating service account '%s'", o.createdAnnotations.ServiceAccountAnnValue())
		if isServiceAccountCreated, err = o.createOrUpdateServiceAccount(client); err != nil {
			return isServiceAccountCreated, isSecretCreated, err
		}

		o.statusUI.PrintMessagef("Creating cluster admin role '%s'", o.createdAnnotations.ClusterRoleAnnValue())
		if err := o.createOrUpdateClusterAdminRole(client); err != nil {
			return isServiceAccountCreated, isSecretCreated, err
		}

		o.statusUI.PrintMessagef("Creating cluster role binding '%s'", o.createdAnnotations.ClusterRoleBindingAnnValue())
		if err := o.createOrUpdateClusterRoleBinding(client); err != nil {
			return isServiceAccountCreated, isSecretCreated, err
		}
	} else {
		client, err := o.depsFactory.CoreClient()
		if err != nil {
			return isServiceAccountCreated, isSecretCreated, err
		}
		svcAccount, err := client.CoreV1().ServiceAccounts(o.NamespaceFlags.Name).Get(context.Background(), o.serviceAccountName, metav1.GetOptions{})
		if err != nil {
			err = fmt.Errorf("Finding service account '%s' in namespace '%s': %s", o.serviceAccountName, o.NamespaceFlags.Name, err.Error())
			return isServiceAccountCreated, isSecretCreated, err
		}

		svcAccountAnnotation, ok := svcAccount.GetAnnotations()[ins.KctrlPkgAnnotation]

		// To support older versions of Tanzu CLI. To be deprecated
		if !ok {
			svcAccountAnnotation, ok = svcAccount.GetAnnotations()[ins.TanzuPkgAnnotation]
		}

		if ok {
			if svcAccountAnnotation != o.createdAnnotations.PackageAnnValue() {
				err = fmt.Errorf("Provided service account '%s' is already used by another package in namespace '%s': %s", o.serviceAccountName, o.NamespaceFlags.Name, err.Error())
				return isServiceAccountCreated, isSecretCreated, err
			}
		}
	}

	if o.valuesFile != "" && o.values {
		o.ui.PrintLinef("Creating secret '%s'", o.createdAnnotations.SecretAnnValue())
		if isSecretCreated, err = o.createOrUpdateDataValuesSecret(client); err != nil {
			return isServiceAccountCreated, isSecretCreated, err
		}
	}

	return isServiceAccountCreated, isSecretCreated, nil
}

func (o *InstallPackageOptions) createOrUpdateServiceAccount(client kubernetes.Interface) (bool, error) {
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      o.createdAnnotations.ServiceAccountAnnValue(),
			Namespace: o.NamespaceFlags.Name,
			Annotations: map[string]string{
				ins.KctrlPkgAnnotation: o.createdAnnotations.PackageAnnValue(),
				ins.TanzuPkgAnnotation: o.createdAnnotations.PackageAnnValue(),
			},
		},
	}

	sa, err := client.CoreV1().ServiceAccounts(o.NamespaceFlags.Name).Create(context.Background(), serviceAccount, metav1.CreateOptions{})
	if err != nil {
		if errors.IsAlreadyExists(err) {
			_, err := client.CoreV1().ServiceAccounts(o.NamespaceFlags.Name).Update(context.Background(), serviceAccount, metav1.UpdateOptions{})
			if err != nil {
				return false, err
			}
		} else {
			return false, err
		}
	}

	fmt.Printf("\n =====> SA created: %+v", sa)
	return true, nil
}

func (o *InstallPackageOptions) createOrUpdateClusterAdminRole(client kubernetes.Interface) error {
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: o.createdAnnotations.ClusterRoleAnnValue(),
			Annotations: map[string]string{
				ins.KctrlPkgAnnotation: o.createdAnnotations.PackageAnnValue(),
				ins.TanzuPkgAnnotation: o.createdAnnotations.PackageAnnValue(),
			},
		},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{"*"}, Verbs: []string{"*"}, Resources: []string{"*"}},
		},
	}

	CR, err := client.RbacV1().ClusterRoles().Create(context.Background(), clusterRole, metav1.CreateOptions{})
	if err != nil {
		if errors.IsAlreadyExists(err) {
			_, err := client.RbacV1().ClusterRoles().Update(context.Background(), clusterRole, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}
	fmt.Printf("\n =====> CR created: %+v", CR)

	return nil
}

func (o *InstallPackageOptions) createOrUpdateClusterRoleBinding(client kubernetes.Interface) error {
	svcAccount := o.serviceAccountName
	if svcAccount == "" {
		svcAccount = o.createdAnnotations.ServiceAccountAnnValue()
	}

	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: o.createdAnnotations.ClusterRoleBindingAnnValue(),
			Annotations: map[string]string{
				ins.KctrlPkgAnnotation: o.createdAnnotations.PackageAnnValue(),
				ins.TanzuPkgAnnotation: o.createdAnnotations.PackageAnnValue(),
			},
		},
		Subjects: []rbacv1.Subject{{Kind: ins.KindServiceAccount.AsString(), Name: svcAccount, Namespace: o.NamespaceFlags.Name}},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.SchemeGroupVersion.Group,
			Kind:     ins.KindClusterRole.AsString(),
			Name:     o.createdAnnotations.ClusterRoleAnnValue(),
		},
	}

	CRB, err := client.RbacV1().ClusterRoleBindings().Create(context.Background(), clusterRoleBinding, metav1.CreateOptions{})
	if err != nil {
		if errors.IsAlreadyExists(err) {
			_, err = client.RbacV1().ClusterRoleBindings().Update(context.Background(), clusterRoleBinding, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	fmt.Printf("\n =====> CRB created: %+v", CRB)

	return nil
}

func (o *InstallPackageOptions) createOrUpdateDataValuesSecret(client kubernetes.Interface) (bool, error) {
	var err error

	dataValues := make(map[string][]byte)

	dataValues[ins.ValuesFileKey], err = cmdcore.NewInputFile(o.valuesFile).Bytes()
	if err != nil {
		return false, fmt.Errorf("Reading data values file '%s': %s", o.valuesFile, err.Error())
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      o.createdAnnotations.SecretAnnValue(),
			Namespace: o.NamespaceFlags.Name,
			Annotations: map[string]string{
				ins.KctrlPkgAnnotation: o.createdAnnotations.PackageAnnValue(),
				ins.TanzuPkgAnnotation: o.createdAnnotations.PackageAnnValue(),
			},
		},
		Data: dataValues,
	}

	_, err = client.CoreV1().Secrets(o.NamespaceFlags.Name).Create(context.Background(), secret, metav1.CreateOptions{})
	if err != nil {
		if errors.IsAlreadyExists(err) {
			_, err := client.CoreV1().Secrets(o.NamespaceFlags.Name).Update(context.Background(), secret, metav1.UpdateOptions{})
			if err != nil {
				return false, err
			}
		} else {
			return false, err
		}
	}

	return true, nil
}

func (o *InstallPackageOptions) createPackageInstall(serviceAccountCreated, secretCreated bool) (*kcpkgv1alpha1.PackageInstall, error) {
	svcAccount := o.serviceAccountName
	if svcAccount == "" {
		svcAccount = o.createdAnnotations.ServiceAccountAnnValue()
	}

	// construct the PackageInstall CR
	packageInstall := &kcpkgv1alpha1.PackageInstall{
		ObjectMeta: metav1.ObjectMeta{Name: o.Name, Namespace: o.NamespaceFlags.Name},
		Spec: kcpkgv1alpha1.PackageInstallSpec{
			ServiceAccountName: svcAccount,
			PackageRef: &kcpkgv1alpha1.PackageRef{
				RefName: o.packageName,
				VersionSelection: &versions.VersionSelectionSemver{
					Constraints: o.version,
					Prereleases: &versions.VersionSelectionSemverPrereleases{},
				},
			},
		},
	}

	// if configuration data file was provided, reference the secret name in the PackageInstall
	if secretCreated {
		packageInstall.Spec.Values = []kcpkgv1alpha1.PackageInstallValues{
			{
				SecretRef: &kcpkgv1alpha1.PackageInstallValuesSecretRef{
					Name: o.createdAnnotations.SecretAnnValue(),
				},
			},
		}
	}

	o.addCreatedResourceAnnotations(&packageInstall.ObjectMeta, serviceAccountCreated, secretCreated)
	return packageInstall, nil
}

func (o *InstallPackageOptions) addCreatedResourceAnnotations(meta *metav1.ObjectMeta, createdSvcAccount, createdSecret bool) {
	if meta.Annotations == nil {
		meta.Annotations = make(map[string]string)
	}
	if createdSvcAccount {
		meta.Annotations[ins.KctrlPkgAnnotation+"-"+ins.KindClusterRole.AsString()] = o.createdAnnotations.ClusterRoleAnnValue()
		meta.Annotations[ins.KctrlPkgAnnotation+"-"+ins.KindClusterRoleBinding.AsString()] = o.createdAnnotations.ClusterRoleBindingAnnValue()
		meta.Annotations[ins.KctrlPkgAnnotation+"-"+ins.KindServiceAccount.AsString()] = o.createdAnnotations.ServiceAccountAnnValue()

		// To support older versions of Tanzu CLI. To be deprecated
		meta.Annotations[ins.TanzuPkgAnnotation+"-"+ins.KindClusterRole.AsString()] = o.createdAnnotations.ClusterRoleAnnValue()
		meta.Annotations[ins.TanzuPkgAnnotation+"-"+ins.KindClusterRoleBinding.AsString()] = o.createdAnnotations.ClusterRoleBindingAnnValue()
		meta.Annotations[ins.TanzuPkgAnnotation+"-"+ins.KindServiceAccount.AsString()] = o.createdAnnotations.ServiceAccountAnnValue()
	}
	if createdSecret {
		meta.Annotations[ins.KctrlPkgAnnotation+"-"+ins.KindSecret.AsString()] = o.createdAnnotations.SecretAnnValue()

		// To support older versions of Tanzu CLI. To be deprecated
		meta.Annotations[ins.TanzuPkgAnnotation+"-"+ins.KindSecret.AsString()] = o.createdAnnotations.SecretAnnValue()
	}
}

func (o *InstallPackageOptions) changePackageNamespace(configs *lclcfg.Configs) error {
	for pkgIdx := range configs.Pkgs {
		configs.Pkgs[pkgIdx].Namespace = o.NamespaceFlags.Name
	}
	return nil
}
