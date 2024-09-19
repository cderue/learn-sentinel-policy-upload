# policy "restrict-aws-instances-type-and-tag" {
#  enforcement_level = "hard-mandatory"
# }

# Import the tfplan/v2 module
import "tfplan/v2" as tfplan

# Define the policy rule
signed_commits = rule {
    all tfplan.resources.github_branch_protection as _, branch {
        all branch.change.after.required_status_checks as _, status {
            status.strict == true and
            "Signed Commit" in status.contexts
        }
    }
}

# Main policy
main = rule {
    signed_commits
}
