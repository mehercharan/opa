package authz.orderstest
import input
import data.orderstest as policies

default allow = false


allow {
  policy = policies[_]
  policy.method = input.method
  policy.path = input.path
  policy.scopes[_] = input.scopes[_]
}

