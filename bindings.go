//go:build !nosilkworm && unix && !(linux && arm64) && !(darwin && amd64)

package silkworm_go

// #cgo CFLAGS: -I${SRCDIR}/include
/*

#include "silkworm.h"
#include <stdlib.h>
#include <string.h>

static bool go_string_copy(_GoString_ s, char *dest, size_t size) {
	size_t len = _GoStringLen(s);
	if (len >= size) return false;
	const char *src = _GoStringPtr(s);
	strncpy(dest, src, len);
	dest[len] = '\0';
	return true;
}

*/
import "C"

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unsafe"
)

const (
	SILKWORM_OK                      = C.SILKWORM_OK
	SILKWORM_INTERNAL_ERROR          = C.SILKWORM_INTERNAL_ERROR
	SILKWORM_UNKNOWN_ERROR           = C.SILKWORM_UNKNOWN_ERROR
	SILKWORM_INVALID_HANDLE          = C.SILKWORM_INVALID_HANDLE
	SILKWORM_INVALID_PATH            = C.SILKWORM_INVALID_PATH
	SILKWORM_INVALID_SNAPSHOT        = C.SILKWORM_INVALID_SNAPSHOT
	SILKWORM_INVALID_MDBX_ENV        = C.SILKWORM_INVALID_MDBX_ENV
	SILKWORM_INVALID_BLOCK_RANGE     = C.SILKWORM_INVALID_BLOCK_RANGE
	SILKWORM_BLOCK_NOT_FOUND         = C.SILKWORM_BLOCK_NOT_FOUND
	SILKWORM_UNKNOWN_CHAIN_ID        = C.SILKWORM_UNKNOWN_CHAIN_ID
	SILKWORM_MDBX_ERROR              = C.SILKWORM_MDBX_ERROR
	SILKWORM_INVALID_BLOCK           = C.SILKWORM_INVALID_BLOCK
	SILKWORM_DECODING_ERROR          = C.SILKWORM_DECODING_ERROR
	SILKWORM_TOO_MANY_INSTANCES      = C.SILKWORM_TOO_MANY_INSTANCES
	SILKWORM_INVALID_SETTINGS        = C.SILKWORM_INVALID_SETTINGS
	SILKWORM_TERMINATION_SIGNAL      = C.SILKWORM_TERMINATION_SIGNAL
	SILKWORM_SERVICE_ALREADY_STARTED = C.SILKWORM_SERVICE_ALREADY_STARTED
	SILKWORM_INCOMPATIBLE_LIBMDBX    = C.SILKWORM_INCOMPATIBLE_LIBMDBX
	SILKWORM_INVALID_MDBX_TXN        = C.SILKWORM_INVALID_MDBX_TXN
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

type Silkworm struct {
	handle C.SilkwormHandle
}

func New(dataDirPath string, libMdbxVersion string, numIOContexts uint32, logVerbosity SilkwormLogLevel) (*Silkworm, error) {
	silkworm := &Silkworm{
		handle: nil,
	}

	settings := &C.struct_SilkwormSettings{
		log_verbosity: C.SilkwormLogLevel(logVerbosity),
		num_contexts:  C.uint32_t(numIOContexts),
	}

	if !C.go_string_copy(dataDirPath, &settings.data_dir_path[0], C.SILKWORM_PATH_SIZE) {
		return nil, errors.New("silkworm.New failed to copy dataDirPath")
	}

	if !C.go_string_copy(libMdbxVersion, &settings.libmdbx_version[0], 32) {
		return nil, errors.New("silkworm.New failed to copy libMdbxVersion")
	}

	status := C.silkworm_init(&silkworm.handle, settings) //nolint:gocritic
	if status == SILKWORM_OK {
		return silkworm, nil
	}
	if status == SILKWORM_INCOMPATIBLE_LIBMDBX {
		silkwormMdbxVersion := C.GoString(C.silkworm_libmdbx_version())
		return nil, fmt.Errorf("silkworm_init error incompatible MDBX: E=%s S=%s", libMdbxVersion, silkwormMdbxVersion)
	}
	return nil, fmt.Errorf("silkworm_init error %d", status)
}

func (s *Silkworm) Close() error {
	status := C.silkworm_fini(s.handle)
	s.handle = nil
	if status == SILKWORM_OK {
		return nil
	}
	return fmt.Errorf("silkworm_fini error %d", status)
}

func memoryMappedFile(file MemoryMappedFile) C.struct_SilkwormMemoryMappedFile {
	return C.struct_SilkwormMemoryMappedFile{
		(*C.char)(file.FilePath.Data),
		(*C.uchar)(file.DataHandle),
		C.uint64_t(file.Size),
	}
}

func (s *Silkworm) AddBlocksSnapshotBundle(bundle BlocksSnapshotBundle) error {
	cBundle := C.struct_SilkwormBlocksSnapshotBundle{
		C.struct_SilkwormHeadersSnapshot{
			memoryMappedFile(bundle.Headers.Segment),
			memoryMappedFile(bundle.Headers.HeaderHashIndex),
		},
		C.struct_SilkwormBodiesSnapshot{
			memoryMappedFile(bundle.Bodies.Segment),
			memoryMappedFile(bundle.Bodies.BlockNumIndex),
		},
		C.struct_SilkwormTransactionsSnapshot{
			memoryMappedFile(bundle.Transactions.Segment),
			memoryMappedFile(bundle.Transactions.TxnHashIndex),
			memoryMappedFile(bundle.Transactions.TxnHash2BlockIndex),
		},
	}

	status := C.silkworm_add_blocks_snapshot_bundle(s.handle, &cBundle) //nolint:gocritic
	if status == SILKWORM_OK {
		return nil
	}
	return fmt.Errorf("silkworm_add_blocks_snapshot_bundle error %d", status)
}

func makeDomainSnapshot(snapshot DomainSnapshot) C.struct_SilkwormDomainSnapshot {
	hasAccessorIndex := snapshot.AccessorIndex != nil
	cSnapshot := C.struct_SilkwormDomainSnapshot{
		memoryMappedFile(snapshot.Segment),
		memoryMappedFile(snapshot.ExistenceIndex),
		memoryMappedFile(snapshot.BTreeIndex),
		C.bool(hasAccessorIndex),
		C.struct_SilkwormMemoryMappedFile{},
	}
	if hasAccessorIndex {
		cSnapshot.accessor_index = memoryMappedFile(*snapshot.AccessorIndex)
	}
	return cSnapshot
}

func (s *Silkworm) AddStateSnapshotBundleLatest(bundle StateSnapshotBundleLatest) error {
	cBundle := C.struct_SilkwormStateSnapshotBundleLatest{
		makeDomainSnapshot(bundle.Accounts),
		makeDomainSnapshot(bundle.Storage),
		makeDomainSnapshot(bundle.Code),
		makeDomainSnapshot(bundle.Commitment),
		makeDomainSnapshot(bundle.Receipts),
	}

	status := C.silkworm_add_state_snapshot_bundle_latest(s.handle, &cBundle) //nolint:gocritic
	if status == SILKWORM_OK {
		return nil
	}
	return fmt.Errorf("silkworm_add_state_snapshot_bundle_latest error %d", status)
}

func makeInvertedIndexSnapshot(snapshot InvertedIndexSnapshot) C.struct_SilkwormInvertedIndexSnapshot {
	return C.struct_SilkwormInvertedIndexSnapshot{
		memoryMappedFile(snapshot.Segment),
		memoryMappedFile(snapshot.AccessorIndex),
	}
}

func makeHistorySnapshot(snapshot HistorySnapshot) C.struct_SilkwormHistorySnapshot {
	return C.struct_SilkwormHistorySnapshot{
		memoryMappedFile(snapshot.Segment),
		memoryMappedFile(snapshot.AccessorIndex),
		makeInvertedIndexSnapshot(snapshot.InvertedIndex),
	}
}

func (s *Silkworm) AddStateSnapshotBundleHistorical(bundle StateSnapshotBundleHistorical) error {
	cBundle := C.struct_SilkwormStateSnapshotBundleHistorical{
		makeHistorySnapshot(bundle.Accounts),
		makeHistorySnapshot(bundle.Storage),
		makeHistorySnapshot(bundle.Code),
		makeHistorySnapshot(bundle.Receipts),

		makeInvertedIndexSnapshot(bundle.LogAddresses),
		makeInvertedIndexSnapshot(bundle.LogTopics),
		makeInvertedIndexSnapshot(bundle.TracesFrom),
		makeInvertedIndexSnapshot(bundle.TracesTo),
	}

	status := C.silkworm_add_state_snapshot_bundle_historical(s.handle, &cBundle) //nolint:gocritic
	if status == SILKWORM_OK {
		return nil
	}
	return fmt.Errorf("silkworm_add_state_snapshot_bundle_historical error %d", status)
}

func (s *Silkworm) LibMdbxVersion() string {
	return C.GoString(C.silkworm_libmdbx_version())
}

type RpcInterfaceLogSettings struct {
	Enabled         bool
	ContainerFolder string
	MaxFileSizeMB   uint16
	MaxFiles        uint16
	DumpResponse    bool
}

func makeCRpcInterfaceLogSettings(settings RpcInterfaceLogSettings) (*C.struct_SilkwormRpcInterfaceLogSettings, error) {
	cSettings := &C.struct_SilkwormRpcInterfaceLogSettings{
		enabled:          C.bool(settings.Enabled),
		max_file_size_mb: C.uint16_t(settings.MaxFileSizeMB),
		max_files:        C.uint16_t(settings.MaxFiles),
		dump_response:    C.bool(settings.DumpResponse),
	}
	if !C.go_string_copy(settings.ContainerFolder, &cSettings.container_folder[0], C.SILKWORM_PATH_SIZE) {
		return nil, errors.New("makeCRpcInterfaceLogSettings failed to copy ContainerFolder")
	}
	return cSettings, nil
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

type ForkValidatorSettings struct {
	BatchSize               uint64
	EtlBufferSize           uint64
	SyncLoopThrottleSeconds uint32
	StopBeforeSendersStage  bool
}

func joinStrings(values []string) string {
	return strings.Join(values[:], ",")
}

func copyCORSDomains(list []string, cList *[C.SILKWORM_RPC_SETTINGS_CORS_DOMAINS_MAX][C.SILKWORM_RPC_SETTINGS_CORS_DOMAIN_SIZE]C.char) error {
	listLen := len(list)
	if listLen > C.SILKWORM_RPC_SETTINGS_CORS_DOMAINS_MAX {
		return errors.New("copyCORSDomains: CORS domain list has too many items")
	}
	// Mark the list end with an empty string
	if listLen < C.SILKWORM_RPC_SETTINGS_CORS_DOMAINS_MAX {
		cList[listLen][0] = 0
	}
	for i, domain := range list {
		if !C.go_string_copy(domain, &cList[i][0], C.SILKWORM_RPC_SETTINGS_CORS_DOMAIN_SIZE) {
			return fmt.Errorf("copyCORSDomains: failed to copy CORS domain %d", i)
		}
	}
	return nil
}

func makeCRpcDaemonSettings(settings RpcDaemonSettings) (*C.struct_SilkwormRpcSettings, error) {
	eth_log_settings, err := makeCRpcInterfaceLogSettings(settings.EthLogSettings)
	if err != nil {
		return nil, err
	}
	cSettings := &C.struct_SilkwormRpcSettings{
		eth_if_log_settings:           *eth_log_settings,
		eth_api_port:                  C.uint16_t(settings.EthAPIPort),
		num_workers:                   C.uint32_t(settings.NumWorkers),
		erigon_json_rpc_compatibility: C.bool(settings.JSONRPCCompatibility),
		ws_enabled:                    C.bool(settings.WebSocketEnabled),
		ws_compression:                C.bool(settings.WebSocketCompression),
		http_compression:              C.bool(settings.HTTPCompression),
		skip_internal_protocol_check:  C.bool(false), // We do check internal protocol versions at startup for sanity
	}
	if !C.go_string_copy(settings.EthAPIHost, &cSettings.eth_api_host[0], C.SILKWORM_RPC_SETTINGS_HOST_SIZE) {
		return nil, errors.New("makeCRpcDaemonSettings failed to copy EthAPIHost")
	}
	if !C.go_string_copy(joinStrings(settings.EthAPISpec), &cSettings.eth_api_spec[0], C.SILKWORM_RPC_SETTINGS_API_NAMESPACE_SPEC_SIZE) {
		return nil, errors.New("makeCRpcDaemonSettings failed to copy EthAPISpec")
	}
	if err := copyCORSDomains(settings.CORSDomains, &cSettings.cors_domains); err != nil {
		return nil, fmt.Errorf("makeCRpcDaemonSettings failed to copy CORSDomains: %w", err)
	}
	if !C.go_string_copy(settings.JWTFilePath, &cSettings.jwt_file_path[0], C.SILKWORM_PATH_SIZE) {
		return nil, errors.New("makeCRpcDaemonSettings failed to copy JWTFilePath")
	}
	return cSettings, nil
}

func (s *Silkworm) StartRpcDaemon(dbEnvCHandle unsafe.Pointer, settings RpcDaemonSettings) error {
	cEnv := (*C.MDBX_env)(dbEnvCHandle)
	cSettings, err := makeCRpcDaemonSettings(settings)
	if err != nil {
		return err
	}
	status := C.silkworm_start_rpcdaemon(s.handle, cEnv, cSettings)
	// Handle successful execution
	if status == SILKWORM_OK {
		return nil
	}
	return fmt.Errorf("silkworm_start_rpcdaemon error %d", status)
}

func (s *Silkworm) StopRpcDaemon() error {
	status := C.silkworm_stop_rpcdaemon(s.handle)
	// Handle successful execution
	if status == SILKWORM_OK {
		return nil
	}
	return fmt.Errorf("silkworm_stop_rpcdaemon error %d", status)
}

func (s *Silkworm) makeForkValidatorSettings(settings ForkValidatorSettings) *C.struct_SilkwormForkValidatorSettings {
	return &C.struct_SilkwormForkValidatorSettings{
		batch_size:                 C.size_t(settings.BatchSize),
		etl_buffer_size:            C.size_t(settings.EtlBufferSize),
		sync_loop_throttle_seconds: C.uint32_t(settings.SyncLoopThrottleSeconds),
		stop_before_senders_stage:  C.bool(settings.StopBeforeSendersStage),
	}
}

func (s *Silkworm) StartForkValidator(dbEnvCHandle unsafe.Pointer, settings ForkValidatorSettings) error {
	cEnv := (*C.MDBX_env)(dbEnvCHandle)
	cSettings := s.makeForkValidatorSettings(settings)

	status := C.silkworm_start_fork_validator(s.handle, cEnv, cSettings)

	if status == SILKWORM_OK {
		return nil
	}

	return fmt.Errorf("silkworm_start_fork_validator error %d", status)
}

func (s *Silkworm) StopForkValidator() error {
	status := C.silkworm_stop_fork_validator(s.handle)

	if status == SILKWORM_OK {
		return nil
	}

	return fmt.Errorf("silkworm_stop_fork_validator error %d", status)
}

type Hash [32]byte

type ExecutionStatus int32

const (
	ExecutionStatus_Success  ExecutionStatus = 0
	ExecutionStatus_BadBlock ExecutionStatus = 1
	ExecutionStatus_Invalid  ExecutionStatus = 4
)

type ForkValidatorValidationResult struct {
	ExecutionStatus ExecutionStatus
	LastValidHash   Hash
	ErrorMessage    string
}

func (s *Silkworm) VerifyChain(headHash Hash) (ForkValidatorValidationResult, error) {
	cHeadHash := C.CBytes(headHash[:])
	defer C.free(cHeadHash)

	cResult := C.struct_SilkwormForkValidatorValidationResult{}

	status := C.silkworm_fork_validator_verify_chain(s.handle, *(*C.struct_SilkwormBytes32)(cHeadHash), &cResult)

	if status == SILKWORM_OK {
		return ForkValidatorValidationResult{
			ExecutionStatus: ExecutionStatus(cResult.execution_status),
			LastValidHash:   *(*Hash)(unsafe.Pointer(&cResult.last_valid_hash)),
			ErrorMessage:    C.GoString((*C.char)(unsafe.Pointer(&cResult.error_message[0]))),
		}, nil
	}

	return ForkValidatorValidationResult{}, fmt.Errorf("silkworm_verify_chain error %d", status)
}

func (s *Silkworm) ForkChoiceUpdate(headHash Hash, finalizedHash Hash, safeHash Hash) error {
	cHeadHash := C.CBytes(headHash[:])
	defer C.free(cHeadHash)

	cFinalizedHash := C.CBytes(finalizedHash[:])
	defer C.free(cFinalizedHash)

	cSafeHash := C.CBytes(safeHash[:])
	defer C.free(cSafeHash)

	status := C.silkworm_fork_validator_fork_choice_update(s.handle, *(*C.struct_SilkwormBytes32)(cHeadHash), *(*C.struct_SilkwormBytes32)(cFinalizedHash), *(*C.struct_SilkwormBytes32)(cSafeHash))

	if status == SILKWORM_OK {
		return nil
	}

	return fmt.Errorf("silkworm_fork_choice_update error %d", status)
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

func copyPeerURLs(list []string, cList *[C.SILKWORM_SENTRY_SETTINGS_PEERS_MAX][C.SILKWORM_SENTRY_SETTINGS_PEER_URL_SIZE]C.char) error {
	listLen := len(list)
	if listLen > C.SILKWORM_SENTRY_SETTINGS_PEERS_MAX {
		return errors.New("copyPeerURLs: peers URL list has too many items")
	}
	// mark the list end with an empty string
	if listLen < C.SILKWORM_SENTRY_SETTINGS_PEERS_MAX {
		cList[listLen][0] = 0
	}
	for i, url := range list {
		if !C.go_string_copy(url, &cList[i][0], C.SILKWORM_SENTRY_SETTINGS_PEER_URL_SIZE) {
			return fmt.Errorf("copyPeerURLs: failed to copy peer URL %d", i)
		}
	}
	return nil
}

func makeCSentrySettings(settings SentrySettings) (*C.struct_SilkwormSentrySettings, error) {
	cSettings := &C.struct_SilkwormSentrySettings{
		api_port:    C.uint16_t(settings.ApiPort),
		port:        C.uint16_t(settings.Port),
		network_id:  C.uint64_t(settings.NetworkId),
		no_discover: C.bool(settings.NoDiscover),
		max_peers:   C.size_t(settings.MaxPeers),
	}
	if !C.go_string_copy(settings.ClientId, &cSettings.client_id[0], C.SILKWORM_SENTRY_SETTINGS_CLIENT_ID_SIZE) {
		return nil, errors.New("makeCSentrySettings failed to copy ClientId")
	}
	if !C.go_string_copy(settings.Nat, &cSettings.nat[0], C.SILKWORM_SENTRY_SETTINGS_NAT_SIZE) {
		return nil, errors.New("makeCSentrySettings failed to copy Nat")
	}
	if len(settings.NodeKey) == C.SILKWORM_SENTRY_SETTINGS_NODE_KEY_SIZE {
		C.memcpy(unsafe.Pointer(&cSettings.node_key[0]), unsafe.Pointer(&settings.NodeKey[0]), C.SILKWORM_SENTRY_SETTINGS_NODE_KEY_SIZE) //nolint:gocritic
	} else {
		return nil, errors.New("makeCSentrySettings failed to copy NodeKey")
	}
	if err := copyPeerURLs(settings.StaticPeers, &cSettings.static_peers); err != nil {
		return nil, fmt.Errorf("copyPeerURLs failed to copy StaticPeers: %w", err)
	}
	if err := copyPeerURLs(settings.Bootnodes, &cSettings.bootnodes); err != nil {
		return nil, fmt.Errorf("copyPeerURLs failed to copy Bootnodes: %w", err)
	}
	return cSettings, nil
}

func (s *Silkworm) SentryStart(settings SentrySettings) error {
	cSettings, err := makeCSentrySettings(settings)
	if err != nil {
		return err
	}
	status := C.silkworm_sentry_start(s.handle, cSettings)
	if status == SILKWORM_OK {
		return nil
	}
	return fmt.Errorf("silkworm_sentry_start error %d", status)
}

func (s *Silkworm) SentryStop() error {
	status := C.silkworm_sentry_stop(s.handle)
	if status == SILKWORM_OK {
		return nil
	}
	return fmt.Errorf("silkworm_sentry_stop error %d", status)
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
	cTxn := (*C.MDBX_txn)(txnCHandle)
	cChainId := C.uint64_t(chainID.Uint64())
	cStartBlock := C.uint64_t(startBlock)
	cMaxBlock := C.uint64_t(maxBlock)
	cBatchSize := C.uint64_t(batchSize)
	cWriteChangeSets := C._Bool(writeChangeSets)
	cWriteReceipts := C._Bool(writeReceipts)
	cWriteCallTraces := C._Bool(writeCallTraces)
	cLastExecutedBlock := C.uint64_t(startBlock - 1)
	cMdbxErrorCode := C.int(0)
	status := C.silkworm_execute_blocks_ephemeral(
		s.handle,
		cTxn,
		cChainId,
		cStartBlock,
		cMaxBlock,
		cBatchSize,
		cWriteChangeSets,
		cWriteReceipts,
		cWriteCallTraces,
		&cLastExecutedBlock,
		&cMdbxErrorCode,
	)
	lastExecutedBlock = uint64(cLastExecutedBlock)
	// Handle successful execution
	if status == SILKWORM_OK {
		return lastExecutedBlock, nil
	}
	// Handle special errors
	if status == SILKWORM_INVALID_BLOCK {
		return lastExecutedBlock, ErrInvalidBlock
	}
	if status == SILKWORM_TERMINATION_SIGNAL {
		return lastExecutedBlock, ErrInterrupted
	}
	return lastExecutedBlock, fmt.Errorf("silkworm_execute_blocks_ephemeral error %d, MDBX error %d", status, cMdbxErrorCode)
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
	cEnv := (*C.MDBX_env)(dbEnvCHandle)
	cChainId := C.uint64_t(chainID.Uint64())
	cStartBlock := C.uint64_t(startBlock)
	cMaxBlock := C.uint64_t(maxBlock)
	cBatchSize := C.uint64_t(batchSize)
	cWriteChangeSets := C._Bool(writeChangeSets)
	cWriteReceipts := C._Bool(writeReceipts)
	cWriteCallTraces := C._Bool(writeCallTraces)
	cLastExecutedBlock := C.uint64_t(startBlock - 1)
	cMdbxErrorCode := C.int(0)
	status := C.silkworm_execute_blocks_perpetual(
		s.handle,
		cEnv,
		cChainId,
		cStartBlock,
		cMaxBlock,
		cBatchSize,
		cWriteChangeSets,
		cWriteReceipts,
		cWriteCallTraces,
		&cLastExecutedBlock,
		&cMdbxErrorCode,
	)
	lastExecutedBlock = uint64(cLastExecutedBlock)
	// Handle successful execution
	if status == SILKWORM_OK {
		return lastExecutedBlock, nil
	}
	// Handle special errors
	if status == SILKWORM_INVALID_BLOCK {
		return lastExecutedBlock, ErrInvalidBlock
	}
	if status == SILKWORM_TERMINATION_SIGNAL {
		return lastExecutedBlock, ErrInterrupted
	}
	return lastExecutedBlock, fmt.Errorf("silkworm_execute_blocks_perpetual error %d, MDBX error %d", status, cMdbxErrorCode)
}

func (s *Silkworm) ExecuteTxn(txCHandle unsafe.Pointer, blockNum uint64, blockHeaderHash Hash, txnIndex uint64, txNum uint64) (gasUsed uint64, blobGasUsed uint64, err error) {
	cTx := (*C.MDBX_txn)(txCHandle)
	cBlockNum := C.uint64_t(blockNum)
	cBlockHeaderHash := C.CBytes(blockHeaderHash[:])
	defer C.free(cBlockHeaderHash)
	cTxnIndex := C.uint64_t(txnIndex)
	cTxnNum := C.uint64_t(txNum)
	cGasUsed := C.uint64_t(0)
	cBlobGasUsed := C.uint64_t(0)
	status := C.silkworm_execute_txn(s.handle, cTx, cBlockNum, *(*C.struct_SilkwormBytes32)(cBlockHeaderHash), cTxnIndex, cTxnNum, &cGasUsed, &cBlobGasUsed)
	gasUsed = uint64(cGasUsed)
	blobGasUsed = uint64(cBlobGasUsed)

	// Handle successful execution
	if status == SILKWORM_OK {
		return gasUsed, blobGasUsed, nil
	}

	return gasUsed, blobGasUsed, fmt.Errorf("silkworm_execute_tx error %d", status)
}
