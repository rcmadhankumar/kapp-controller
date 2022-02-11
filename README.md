![logo](docs/CarvelLogo.png)
  
# kapp-controller

Kubernetes native continuous delivery and package management experience through custom resource definitions.

<p>
<a href="https://carvel.dev/kapp-controller/docs/latest">Documentation</a> ·
<a href="https://app.zenhub.com/workspaces/carvel-backlog-6013063a24147d0011410709/board?repos=220090417">Backlog</a> ·
<a href="https://kubernetes.slack.com/archives/CH8KCCKA5">Slack</a> ·
<a href="https://twitter.com/carvel_dev">Twitter</a>
</p>

## Features

:zap: **Kubernetes Package Management** :zap:
- [Authoring software packages](https://carvel.dev/kapp-controller/docs/latest/package-authoring/) through `Package` and `PackageMetadata` custom resources
- [Consuming software packages](https://carvel.dev/kapp-controller/docs/latest/package-consumption/) through `PackageRepository` and `PackageInstall` custom resources

:truck: **Continuous Delivery** :truck:
  - Declarative installation, management, and upgrading of applications on a Kubernetes cluster using the [App CRD](https://carvel.dev/kapp-controller/docs/latest/app-overview/#app)
  - [Fetchable resources](https://carvel.dev/kapp-controller/docs/latest/app-overview/#specfetch) are continuously monitored and the cluster is updated to reflect any change
  - [Checkout our tutorial](https://carvel.dev/kapp-controller/docs/latest/walkthrough/)

:octocat: **GitOps** :octocat:
  - Our Continous Delivery mechanism is perfect for GitOps!
  - Use a git repository as your single source of truth for Kubernetes Package Management
  - [Checkout our tutorial](https://carvel.dev/kapp-controller/docs/latest/packaging-gitops/)

## Contribute

Check out our [contributing guidelines](CONTRIBUTING.md).

Detailed instructions on how to setup and test locally can be found in our [developer guide](docs/dev.md).

### Join the Community and Make Carvel Better

Carvel is better because of our contributors and maintainers. It is because of you that we can bring great software to the community.
Please join us during our online community meetings. Details can be found on our [Carvel website](https://carvel.dev/community/).

You can chat with us on Kubernetes Slack in the #carvel channel and follow us on Twitter at @carvel_dev.

Check out which organizations are using and contributing to Carvel: [Adopter's list](https://github.com/vmware-tanzu/carvel/blob/master/ADOPTERS.md)
