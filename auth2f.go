package Security

import (
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"
)

type Auth2FCode struct {
	Code     string
	Lifespan int
	Created  time.Time
}

func (a *Auth2FCode) IsExpired() bool {
	now := time.Now()
	expiredAt := a.Created.Add(time.Duration(a.Lifespan) * time.Second)

	return expiredAt.Before(now)
}

type Auth2FGroup struct {
	codesLock *sync.Mutex
	codes     map[string]Auth2FCode
}

func (a *Auth2FGroup) Generate(key string, digits int, lifespan int) Auth2FCode {

	now := time.Now()

	rand.Seed(time.Now().UnixNano())
	min := int(math.Pow(10, float64(digits-1)))
	max := int(math.Pow(10, float64(digits))) - 1

	a.codesLock.Lock()
	a.codes[key] = Auth2FCode{
		Code:     fmt.Sprintf("%v", rand.Intn(max-min+1)+min),
		Created:  now,
		Lifespan: lifespan,
	}
	a.codesLock.Unlock()

	return a.codes[key]
}

func (a *Auth2FGroup) Remove(key string) bool {

	a.codesLock.Lock()
	if _, found := a.codes[key]; found {
		delete(a.codes, key)
	} else {
		return false
	}
	a.codesLock.Unlock()

	return true
}

func (a *Auth2FGroup) Iterate(fnc func(key string, code Auth2FCode)) {
	for k, c := range a.codes {
		nc := Auth2FCode{
			Code:     c.Code,
			Created:  c.Created,
			Lifespan: c.Lifespan,
		}
		fnc(k, nc)
	}
}

func (a *Auth2FGroup) RemoveExpired(fnc func(key string, code Auth2FCode)) {
	a.Iterate(func(key string, code Auth2FCode) {
		if code.IsExpired() {
			a.Remove(key)
		}
	})
}

func NewAuth2FGroup() Auth2FGroup {
	a2f := Auth2FGroup{
		codesLock: &sync.Mutex{},
		codes:     map[string]Auth2FCode{},
	}

	return a2f
}
