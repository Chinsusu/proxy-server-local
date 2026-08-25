// Package application owns use cases between the HTTP transports and the
// SQLite domain store. It is intentionally thin: authorization is transport
// specific, but idempotency, versioned mutations and agent snapshots are not.
package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Chinsusu/proxy-server-local/internal/domain"
	"github.com/Chinsusu/proxy-server-local/internal/persistence/sqlite"
	"github.com/Chinsusu/proxy-server-local/pkg/check"
)

type Service struct{ repository *sqlite.Repository }

func New(repository *sqlite.Repository) *Service { return &Service{repository: repository} }

func (s *Service) Repository() *sqlite.Repository { return s.repository }

func requestHash(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }

func marshalResult(value any) ([]byte, error) { return json.Marshal(value) }

func (s *Service) CreateProxy(ctx context.Context, input sqlite.CreateProxyInput, idempotencyKey string, rawRequest []byte) (domain.Proxy, bool, error) {
	var result domain.Proxy
	response, replay, err := s.repository.ExecuteIdempotent(ctx, "proxy.create", idempotencyKey, requestHash(rawRequest), func(ctx context.Context, uow *sqlite.UnitOfWork) ([]byte, error) {
		proxy, err := uow.CreateProxy(ctx, input)
		if err != nil {
			return nil, err
		}
		return marshalResult(proxy)
	})
	if err != nil {
		return result, false, err
	}
	if err := json.Unmarshal(response, &result); err != nil {
		return result, false, fmt.Errorf("decode stored proxy response: %w", err)
	}
	return result, replay, nil
}

func (s *Service) CreateClient(ctx context.Context, input sqlite.CreateClientInput, idempotencyKey string, rawRequest []byte) (domain.Client, bool, error) {
	var result domain.Client
	response, replay, err := s.repository.ExecuteIdempotent(ctx, "client.create", idempotencyKey, requestHash(rawRequest), func(ctx context.Context, uow *sqlite.UnitOfWork) ([]byte, error) {
		client, err := uow.CreateClient(ctx, input)
		if err != nil {
			return nil, err
		}
		return marshalResult(client)
	})
	if err != nil {
		return result, false, err
	}
	if err := json.Unmarshal(response, &result); err != nil {
		return result, false, fmt.Errorf("decode stored client response: %w", err)
	}
	return result, replay, nil
}

func (s *Service) CreateMapping(ctx context.Context, input sqlite.CreateMappingInput, idempotencyKey string, rawRequest []byte) (domain.Mapping, bool, error) {
	var result domain.Mapping
	response, replay, err := s.repository.ExecuteIdempotent(ctx, "mapping.create", idempotencyKey, requestHash(rawRequest), func(ctx context.Context, uow *sqlite.UnitOfWork) ([]byte, error) {
		mapping, err := uow.CreateMapping(ctx, input)
		if err != nil {
			return nil, err
		}
		return marshalResult(mapping)
	})
	if err != nil {
		return result, false, err
	}
	if err := json.Unmarshal(response, &result); err != nil {
		return result, false, fmt.Errorf("decode stored mapping response: %w", err)
	}
	return result, replay, nil
}

// CreateAndActivateMapping is the narrowly scoped legacy v1 bridge. The old
// create endpoint expected an immediately usable mapping; the v2 contract uses
// draft then activate. This bridge performs both state changes, generation
// bump, validation and audit in one idempotent immediate transaction.
func (s *Service) CreateAndActivateMapping(ctx context.Context, input sqlite.CreateMappingInput, idempotencyKey string, rawRequest []byte) (domain.Mapping, bool, error) {
	var result domain.Mapping
	response, replay, err := s.repository.ExecuteIdempotent(ctx, "mapping.legacy-create-active", idempotencyKey, requestHash(rawRequest), func(ctx context.Context, uow *sqlite.UnitOfWork) ([]byte, error) {
		if input.LocalRedirectPort == 0 {
			var err error
			input.LocalRedirectPort, err = uow.AllocateLegacyRedirectPort(ctx)
			if err != nil {
				return nil, err
			}
		}
		mapping, err := uow.CreateMapping(ctx, input)
		if err != nil {
			return nil, err
		}
		mapping, err = uow.ActivateMapping(ctx, mapping.ID, input.Actor)
		if err != nil {
			return nil, err
		}
		return marshalResult(mapping)
	})
	if err != nil {
		return result, false, err
	}
	if err := json.Unmarshal(response, &result); err != nil {
		return result, false, fmt.Errorf("decode stored legacy mapping response: %w", err)
	}
	return result, replay, nil
}

func (s *Service) ActivateMapping(ctx context.Context, mappingID string, version int64, actor, idempotencyKey string, rawRequest []byte) (domain.Mapping, bool, error) {
	var result domain.Mapping
	response, replay, err := s.repository.ExecuteIdempotent(ctx, "mapping.activate:"+mappingID, idempotencyKey, requestHash(rawRequest), func(ctx context.Context, uow *sqlite.UnitOfWork) ([]byte, error) {
		if err := uow.RequireMappingVersion(ctx, mappingID, version); err != nil {
			return nil, err
		}
		mapping, err := uow.ActivateMapping(ctx, mappingID, actor)
		if err != nil {
			return nil, err
		}
		return marshalResult(mapping)
	})
	if err != nil {
		return result, false, err
	}
	if err := json.Unmarshal(response, &result); err != nil {
		return result, false, fmt.Errorf("decode stored activation response: %w", err)
	}
	return result, replay, nil
}

func (s *Service) SuspendMapping(ctx context.Context, mappingID string, version int64, actor, idempotencyKey string, rawRequest []byte) (domain.Mapping, bool, error) {
	var result domain.Mapping
	response, replay, err := s.repository.ExecuteIdempotent(ctx, "mapping.suspend:"+mappingID, idempotencyKey, requestHash(rawRequest), func(ctx context.Context, uow *sqlite.UnitOfWork) ([]byte, error) {
		if err := uow.RequireMappingVersion(ctx, mappingID, version); err != nil {
			return nil, err
		}
		mapping, err := uow.TransitionMapping(ctx, mappingID, domain.DesiredSuspended, actor)
		if err != nil {
			return nil, err
		}
		return marshalResult(mapping)
	})
	if err != nil {
		return result, false, err
	}
	if err := json.Unmarshal(response, &result); err != nil {
		return result, false, fmt.Errorf("decode stored suspension response: %w", err)
	}
	return result, replay, nil
}

func (s *Service) DeleteMapping(ctx context.Context, mappingID string, version int64, actor, idempotencyKey string, rawRequest []byte) (domain.Mapping, bool, error) {
	var result domain.Mapping
	response, replay, err := s.repository.ExecuteIdempotent(ctx, "mapping.delete:"+mappingID, idempotencyKey, requestHash(rawRequest), func(ctx context.Context, uow *sqlite.UnitOfWork) ([]byte, error) {
		if err := uow.RequireMappingVersion(ctx, mappingID, version); err != nil {
			return nil, err
		}
		mapping, err := uow.TransitionMapping(ctx, mappingID, domain.DesiredDeleted, actor)
		if err != nil {
			return nil, err
		}
		return marshalResult(mapping)
	})
	if err != nil {
		return result, false, err
	}
	if err := json.Unmarshal(response, &result); err != nil {
		return result, false, fmt.Errorf("decode stored delete response: %w", err)
	}
	return result, replay, nil
}

func (s *Service) PatchProxy(ctx context.Context, id string, version int64, input sqlite.PatchProxyInput, idempotencyKey string, rawRequest []byte) (domain.Proxy, bool, error) {
	var result domain.Proxy
	response, replay, err := s.repository.ExecuteIdempotent(ctx, "proxy.patch:"+id, idempotencyKey, requestHash(rawRequest), func(ctx context.Context, uow *sqlite.UnitOfWork) ([]byte, error) {
		proxy, err := uow.PatchProxyIfVersion(ctx, id, version, input)
		if err != nil {
			return nil, err
		}
		return marshalResult(proxy)
	})
	if err != nil {
		return result, false, err
	}
	if err := json.Unmarshal(response, &result); err != nil {
		return result, false, fmt.Errorf("decode stored proxy patch response: %w", err)
	}
	return result, replay, nil
}

func (s *Service) PatchClient(ctx context.Context, id string, version int64, input sqlite.PatchClientInput, idempotencyKey string, rawRequest []byte) (domain.Client, bool, error) {
	var result domain.Client
	response, replay, err := s.repository.ExecuteIdempotent(ctx, "client.patch:"+id, idempotencyKey, requestHash(rawRequest), func(ctx context.Context, uow *sqlite.UnitOfWork) ([]byte, error) {
		client, err := uow.PatchClientIfVersion(ctx, id, version, input)
		if err != nil {
			return nil, err
		}
		return marshalResult(client)
	})
	if err != nil {
		return result, false, err
	}
	if err := json.Unmarshal(response, &result); err != nil {
		return result, false, fmt.Errorf("decode stored client patch response: %w", err)
	}
	return result, replay, nil
}

func (s *Service) PatchMapping(ctx context.Context, id string, version int64, input sqlite.PatchMappingInput, idempotencyKey string, rawRequest []byte) (domain.Mapping, bool, error) {
	var result domain.Mapping
	response, replay, err := s.repository.ExecuteIdempotent(ctx, "mapping.patch:"+id, idempotencyKey, requestHash(rawRequest), func(ctx context.Context, uow *sqlite.UnitOfWork) ([]byte, error) {
		mapping, err := uow.PatchMappingIfVersion(ctx, id, version, input)
		if err != nil {
			return nil, err
		}
		return marshalResult(mapping)
	})
	if err != nil {
		return result, false, err
	}
	if err := json.Unmarshal(response, &result); err != nil {
		return result, false, fmt.Errorf("decode stored mapping patch response: %w", err)
	}
	return result, replay, nil
}

func (s *Service) DeleteProxy(ctx context.Context, id string, version int64, actor, idempotencyKey string, rawRequest []byte) (bool, error) {
	_, replay, err := s.repository.ExecuteIdempotent(ctx, "proxy.delete:"+id, idempotencyKey, requestHash(rawRequest), func(ctx context.Context, uow *sqlite.UnitOfWork) ([]byte, error) {
		if err := uow.DeleteProxyIfVersion(ctx, id, version, actor); err != nil {
			return nil, err
		}
		return []byte(`{}`), nil
	})
	return replay, err
}

func (s *Service) DeleteClient(ctx context.Context, id string, version int64, actor, idempotencyKey string, rawRequest []byte) (bool, error) {
	_, replay, err := s.repository.ExecuteIdempotent(ctx, "client.delete:"+id, idempotencyKey, requestHash(rawRequest), func(ctx context.Context, uow *sqlite.UnitOfWork) ([]byte, error) {
		if err := uow.DeleteClientIfVersion(ctx, id, version, actor); err != nil {
			return nil, err
		}
		return []byte(`{}`), nil
	})
	return replay, err
}

func (s *Service) DesiredSnapshot(ctx context.Context) (domain.DesiredSnapshot, error) {
	return s.repository.DesiredSnapshot(ctx)
}
func (s *Service) CredentialForActiveMapping(ctx context.Context, mappingID string) (domain.AgentCredential, error) {
	return s.repository.GetActiveMappingCredential(ctx, mappingID)
}
func (s *Service) AcknowledgeAgent(ctx context.Context, ack domain.AgentAck, actor string) (domain.ReconcileState, error) {
	return s.repository.AcknowledgeAgent(ctx, ack, actor)
}

// ProxyCheckResult is the redacted v1 compatibility probe response. It never
// contains a credential or an unbounded upstream error string.
type ProxyCheckResult struct {
	Status    string `json:"status"`
	LatencyMS int    `json:"latency_ms"`
	ExitIP    string `json:"exit_ip"`
}

// CheckProxy is a bounded direct diagnostic used only by the legacy v1 check
// endpoint. It reads the optional encrypted credential just-in-time, does not
// write plaintext to state/logs/audit, and stores only redacted health facts.
func (s *Service) CheckProxy(ctx context.Context, proxyID string) (ProxyCheckResult, error) {
	proxy, err := s.repository.GetProxy(ctx, proxyID)
	if err != nil {
		return ProxyCheckResult{}, err
	}
	credential, err := s.repository.GetProxyCredential(ctx, proxyID)
	if err != nil {
		return ProxyCheckResult{}, err
	}
	defer zeroBytes(credential.Password)
	probeContext, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	var username *string
	var password []byte
	if proxy.PasswordConfigured {
		// The probe receives the mutable credential directly; no application DTO
		// turns the password into an immutable Go string.
		usernameValue := credential.Username
		username, password = &usernameValue, credential.Password
	}
	var checkResult check.Result
	if proxy.Type == domain.ProxySOCKS5 {
		checkResult = check.CheckSOCKS5(probeContext, proxy.Host, proxy.Port, username, &password)
	} else {
		checkResult = check.CheckHTTP(probeContext, proxy.Host, proxy.Port, username, &password)
	}
	status := domain.ProxyStatus(checkResult.Status)
	reasonCode := ""
	if checkResult.Err != nil {
		status = domain.ProxyStatusDown
		reasonCode = "probe_failed"
	}
	if err := s.repository.RecordProxyHealth(ctx, proxyID, status, checkResult.LatencyMs, checkResult.ExitIP, reasonCode); err != nil {
		return ProxyCheckResult{}, err
	}
	return ProxyCheckResult{Status: string(status), LatencyMS: checkResult.LatencyMs, ExitIP: checkResult.ExitIP}, nil
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
