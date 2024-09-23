//go:build nosilkworm || windows || (linux && arm64) || (darwin && amd64)

package silkworm_go

import (
	"errors"
	"math/big"
	"unsafe"
)

// ErrInterrupted is the error returned by Silkworm APIs when stopped by any termination signal.
var ErrInterrupted = errors.New("interrupted")
var ErrInvalidBlock = errors.New("invalid block")

type SilkwormLogLevel uint32

const (
	LogLevelNone SilkwormLogLevel = iota
	LogLevelCritical
	LogLevelError
	LogLevelWarning
	LogLevelInfo
	LogLevelDebug
	LogLevelTrace
)

type RpcInterfaceLogSettings struct {
	Enabled         bool
	ContainerFolder string
	MaxFileSizeMB   uint16
	MaxFiles        uint16
	DumpResponse    bool
}

type RpcDaemonSettings struct {
	EthLogSettings       RpcInterfaceLogSettings
	EthAPIHost           string
	EthAPIPort           int
	EthAPISpec           []string
	NumWorkers           uint32
	CORSDomains          []string
	JWTFilePath          string
	JSONRPCCompatibility bool
	WebSocketEnabled     bool
	WebSocketCompression bool
	HTTPCompression      bool
}

type Silkworm struct {
}

func New(dataDirPath string, libMdbxVersion string, numIOContexts uint32, logVerbosity SilkwormLogLevel) (*Silkworm, error) {
	return nil, errors.New("silkworm is not supported")
}

func (s *Silkworm) Close() error {
	return nil
}

func (s *Silkworm) AddSnapshot(snapshot *MappedChainSnapshot) error {
	return nil
}

func (s *Silkworm) StartRpcDaemon(dbEnvCHandle unsafe.Pointer, settings RpcDaemonSettings) error {
	return nil
}

func (s *Silkworm) StopRpcDaemon() error {
	return nil
}

type SentrySettings struct {
	ClientId    string
	ApiPort     int
	Port        int
	Nat         string
	NetworkId   uint64
	NodeKey     []byte
	StaticPeers []string
	Bootnodes   []string
	NoDiscover  bool
	MaxPeers    int
}

func (s *Silkworm) SentryStart(settings SentrySettings) error {
	return nil
}

func (s *Silkworm) SentryStop() error {
	return nil
}

func (s *Silkworm) ExecuteBlocksEphemeral(
	txnCHandle unsafe.Pointer,
	chainID *big.Int,
	startBlock uint64,
	maxBlock uint64,
	batchSize uint64,
	writeChangeSets,
	writeReceipts,
	writeCallTraces bool,
) (lastExecutedBlock uint64, err error) {
	return 0, nil
}

func (s *Silkworm) ExecuteBlocksPerpetual(
	dbEnvCHandle unsafe.Pointer,
	chainID *big.Int,
	startBlock uint64,
	maxBlock uint64,
	batchSize uint64,
	writeChangeSets,
	writeReceipts,
	writeCallTraces bool,
) (lastExecutedBlock uint64, err error) {
	return 0, nil
}
