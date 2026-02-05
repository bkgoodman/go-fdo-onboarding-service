module fdo-manufacturing-station

go 1.25.0

require (
	github.com/fido-device-onboard/go-fdo v0.0.0
	github.com/fido-device-onboard/go-fdo/fsim v0.0.0-20260116133239-94bd9c5d647c
	github.com/fido-device-onboard/go-fdo/sqlite v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/ncruces/go-sqlite3 v0.30.4 // indirect
	github.com/ncruces/julianday v1.0.0 // indirect
	github.com/tetratelabs/wazero v1.11.0 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
)

replace github.com/fido-device-onboard/go-fdo => ./go-fdo

replace github.com/fido-device-onboard/go-fdo/sqlite => ./go-fdo/sqlite

replace github.com/fido-device-onboard/go-fdo/fsim => ./go-fdo/fsim
