/*
Copyright 2021 Wim Henderickx.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import "fmt"

// EmptyTargetAddressError is returned when the Target address field
// for a network node is empty
type EmptyTargetAddressError struct {
	message string
}

func (e EmptyTargetAddressError) Error() string {
	return fmt.Sprintf("Empty Target address %s",
		e.message)
}

// EmptyTargetSecretError is returned when the Target secret
// for a network node is empty
type EmptyTargetSecretError struct {
	message string
}

func (e EmptyTargetSecretError) Error() string {
	return fmt.Sprintf("No Target CredentialsName defined %s",
		e.message)
}

// ResolveTargetSecretRefError is returned when the Target secret
// for a network node is defined but cannot be found
type ResolveTargetSecretRefError struct {
	message string
}

func (e ResolveTargetSecretRefError) Error() string {
	return fmt.Sprintf("Target CredentialsName secret doesn't exist %s",
		e.message)
}
