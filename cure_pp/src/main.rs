use cure_pp::{cure_repo, repository_util::{self, RepoConfig}};

pub fn main(){
    repository_util::clear_repo(&RepoConfig::default());

    // println!("Creating repositories. If this is the first run, key generation might take a while...");
    let repo = cure_repo::default_repo_c_irpki(5000, 5001, true);
    repo.write_to_disc();

    let repo2 = cure_repo::default_repo_c(5000, 1, true);
    repo2.write_to_disc();
    repo2.get_tal();
}