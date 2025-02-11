package silkworm_go

import "unsafe"

var NewFilePath = NewCString

type MemoryMappedFile struct {
	FilePath   *CString
	DataHandle unsafe.Pointer
	Size       int64
}

type HeadersSnapshot struct {
	Segment         MemoryMappedFile
	HeaderHashIndex MemoryMappedFile
}

type BodiesSnapshot struct {
	Segment       MemoryMappedFile
	BlockNumIndex MemoryMappedFile
}

type TransactionsSnapshot struct {
	Segment            MemoryMappedFile
	TxnHashIndex       MemoryMappedFile
	TxnHash2BlockIndex MemoryMappedFile
}

type BlocksSnapshotBundle struct {
	Headers      HeadersSnapshot
	Bodies       BodiesSnapshot
	Transactions TransactionsSnapshot
}

type InvertedIndexSnapshot struct {
	Segment       MemoryMappedFile // .ef
	AccessorIndex MemoryMappedFile // .efi
}

type HistorySnapshot struct {
	Segment       MemoryMappedFile // .v
	AccessorIndex MemoryMappedFile // .vi
	InvertedIndex InvertedIndexSnapshot
}

type DomainSnapshot struct {
	Segment        MemoryMappedFile  // .kv
	ExistenceIndex MemoryMappedFile  // .kvei
	BTreeIndex     MemoryMappedFile  // .bt
	AccessorIndex  *MemoryMappedFile // .kvi
}

type StateSnapshotBundleLatest struct {
	Accounts   DomainSnapshot
	Storage    DomainSnapshot
	Code       DomainSnapshot
	Commitment DomainSnapshot
	Receipts   DomainSnapshot
}

type StateSnapshotBundleHistorical struct {
	Accounts HistorySnapshot
	Storage  HistorySnapshot
	Code     HistorySnapshot
	Receipts HistorySnapshot

	LogAddresses InvertedIndexSnapshot
	LogTopics    InvertedIndexSnapshot
	TracesFrom   InvertedIndexSnapshot
	TracesTo     InvertedIndexSnapshot
}
