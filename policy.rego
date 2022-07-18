package example.authz

import data.all_authenticated_users
import data.premium_users

default allow := false

allow {
	startswith(input.path, "/details/") == true
	lower(input.subject.user) == all_authenticated_users[_]
}

allow {
	startswith(input.path, "/reviews/") == true
	lower(input.subject.user) == premium_users[_]
}
