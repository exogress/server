pub struct AclName(String);
pub struct EnvironmentName(String);

pub struct Requirements {
    acls: Vec<AclName>, // list of ACL names which should be defined
    default_acl: AclName,
}

pub struct Environment {
    name: EnvironmentName,
    acls: Vec<Acl>,
}

pub struct Acl {
    name: AclName,
    provider: ProviderRules,
}

pub enum ProviderRules {
    Google(GoogleAcl),
    Github(GithubAcl),
}

pub struct GoogleAcl {}

pub struct GithubAcl {
    allowed_logins: GithubAllowedLogins,
}

pub enum GithubAllowedLogins {
    Anybody,
    Users(Vec<String>),
}
