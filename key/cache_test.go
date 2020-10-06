/**
 * Copyright 2020 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package key

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func makeExpectedPairs(count int) (expectedKeyIDs []string, expectedPairs map[string]Pair) {
	expectedPairs = make(map[string]Pair, count)
	for index := 0; index < count; index++ {
		keyID := fmt.Sprintf("key#%d", index)
		expectedKeyIDs = append(expectedKeyIDs, keyID)
		expectedPairs[keyID] = &MockPair{}
	}

	return
}

func assertExpectationsForPairs(t *testing.T, pairs map[string]Pair) {
	for _, pair := range pairs {
		if mockPair, ok := pair.(*MockPair); ok {
			mock.AssertExpectationsForObjects(t, mockPair.Mock)
		}
	}
}

func TestBasicCacheStoreAndLoad(t *testing.T) {
	assert := assert.New(t)

	cache := basicCache{}
	assert.Nil(cache.load())
	cache.store(123)
	assert.Equal(123, cache.load())
}

func TestSingleCacheResolveKey(t *testing.T) {
	assert := assert.New(t)

	const keyID = "TestSingleCacheResolveKey"
	expectedPair := &MockPair{}
	resolver := &MockResolver{}
	resolver.On("ResolveKey", mock.Anything, keyID).Return(expectedPair, nil).Once()

	cache := singleCache{
		basicCache{
			delegate: resolver,
		},
	}

	waitGroup := &sync.WaitGroup{}
	waitGroup.Add(2)
	barrier := make(chan struct{})

	for repeat := 0; repeat < 2; repeat++ {
		go func() {
			defer waitGroup.Done()
			<-barrier
			actualPair, err := cache.ResolveKey(context.Background(), keyID)
			assert.Equal(expectedPair, actualPair)
			assert.Nil(err)
		}()
	}

	close(barrier)
	waitGroup.Wait()

	mock.AssertExpectationsForObjects(t, expectedPair.Mock)
	mock.AssertExpectationsForObjects(t, resolver.Mock)
	assert.Equal(expectedPair, cache.load())
}

func TestSingleCacheResolveKeyError(t *testing.T) {
	assert := assert.New(t)

	const keyID = "TestSingleCacheResolveKeyError"
	expectedError := errors.New("TestSingleCacheResolveKeyError")
	resolver := &MockResolver{}
	resolver.On("ResolveKey", mock.Anything, keyID).Return(nil, expectedError).Twice()

	cache := singleCache{
		basicCache{
			delegate: resolver,
		},
	}

	waitGroup := &sync.WaitGroup{}
	waitGroup.Add(2)
	barrier := make(chan struct{})

	for repeat := 0; repeat < 2; repeat++ {
		go func() {
			defer waitGroup.Done()
			<-barrier
			pair, err := cache.ResolveKey(context.Background(), keyID)
			assert.Nil(pair)
			assert.Equal(expectedError, err)
		}()
	}

	close(barrier)
	waitGroup.Wait()

	mock.AssertExpectationsForObjects(t, resolver.Mock)
	assert.Nil(cache.load())
}

func TestSingleCacheUpdateKeys(t *testing.T) {
	assert := assert.New(t)

	expectedPair := &MockPair{}
	resolver := &MockResolver{}
	resolver.On("ResolveKey", mock.Anything, dummyKeyId).Return(expectedPair, nil).Once()

	cache := singleCache{
		basicCache{
			delegate: resolver,
		},
	}

	count, errors := cache.UpdateKeys(context.Background())
	mock.AssertExpectationsForObjects(t, expectedPair.Mock)
	mock.AssertExpectationsForObjects(t, resolver.Mock)
	assert.Equal(1, count)
	assert.Nil(errors)
}

func TestSingleCacheUpdateKeysError(t *testing.T) {
	assert := assert.New(t)

	expectedError := errors.New("TestSingleCacheUpdateKeysError")
	resolver := &MockResolver{}
	resolver.On("ResolveKey", mock.Anything, dummyKeyId).Return(nil, expectedError).Once()

	cache := singleCache{
		basicCache{
			delegate: resolver,
		},
	}

	count, errors := cache.UpdateKeys(context.Background())
	mock.AssertExpectationsForObjects(t, resolver.Mock)
	assert.Equal(1, count)
	assert.Equal([]error{expectedError}, errors)

	mock.AssertExpectationsForObjects(t, resolver.Mock)
}

func TestSingleCacheUpdateKeysSequence(t *testing.T) {
	assert := assert.New(t)

	const keyID = "TestSingleCacheUpdateKeysSequence"
	expectedError := errors.New("TestSingleCacheUpdateKeysSequence")
	oldPair := &MockPair{}
	newPair := &MockPair{}
	resolver := &MockResolver{}
	resolver.On("ResolveKey", mock.Anything, keyID).Return(oldPair, nil).Once()
	resolver.On("ResolveKey", mock.Anything, dummyKeyId).Return(nil, expectedError).Once()
	resolver.On("ResolveKey", mock.Anything, dummyKeyId).Return(newPair, nil).Once()

	cache := singleCache{
		basicCache{
			delegate: resolver,
		},
	}

	firstPair, err := cache.ResolveKey(context.Background(), keyID)
	assert.Equal(oldPair, firstPair)
	assert.Nil(err)

	count, errors := cache.UpdateKeys(context.Background())
	assert.Equal(1, count)
	assert.Equal([]error{expectedError}, errors)

	// resolving should pull the key from the cache
	firstPair, err = cache.ResolveKey(context.Background(), keyID)
	assert.Equal(oldPair, firstPair)
	assert.Nil(err)

	// this time, the mock will succeed
	count, errors = cache.UpdateKeys(context.Background())
	assert.Equal(1, count)
	assert.Len(errors, 0)

	// resolving should pull the *new* key from the cache
	secondPair, err := cache.ResolveKey(context.Background(), keyID)
	assert.Equal(newPair, secondPair)
	assert.Nil(err)

	mock.AssertExpectationsForObjects(t, resolver.Mock)
}

func TestMultiCacheResolveKey(t *testing.T) {
	assert := assert.New(t)

	expectedKeyIDs, expectedPairs := makeExpectedPairs(2)
	resolver := &MockResolver{}
	for _, keyID := range expectedKeyIDs {
		resolver.On("ResolveKey", mock.Anything, keyID).Return(expectedPairs[keyID], nil).Once()
	}

	cache := multiCache{
		basicCache{
			delegate: resolver,
		},
	}

	// spawn twice the number of routines as keys so
	// that we test concurrently resolving keys from the cache
	// and from the delegate
	waitGroup := &sync.WaitGroup{}
	waitGroup.Add(5 * len(expectedKeyIDs))
	barrier := make(chan struct{})

	for repeat := 0; repeat < 5; repeat++ {
		for _, keyID := range expectedKeyIDs {
			go func(keyID string, expectedPair Pair) {
				t.Logf("keyID=%s", keyID)
				defer waitGroup.Done()
				<-barrier
				pair, err := cache.ResolveKey(context.Background(), keyID)
				assert.Equal(expectedPair, pair)
				assert.Nil(err)
			}(keyID, expectedPairs[keyID])
		}
	}

	close(barrier)
	waitGroup.Wait()

	mock.AssertExpectationsForObjects(t, resolver.Mock)
	assertExpectationsForPairs(t, expectedPairs)
}

func TestMultiCacheResolveKeyError(t *testing.T) {
	assert := assert.New(t)

	expectedError := errors.New("TestMultiCacheResolveKeyError")
	expectedKeyIDs, _ := makeExpectedPairs(2)
	resolver := &MockResolver{}
	for _, keyID := range expectedKeyIDs {
		resolver.On("ResolveKey", mock.Anything, keyID).Return(nil, expectedError).Twice()
	}

	cache := multiCache{
		basicCache{
			delegate: resolver,
		},
	}

	// spawn twice the number of routines as keys so
	// that we test concurrently resolving keys from the cache
	// and from the delegate
	waitGroup := &sync.WaitGroup{}
	waitGroup.Add(2 * len(expectedKeyIDs))
	barrier := make(chan struct{})

	for repeat := 0; repeat < 2; repeat++ {
		for _, keyID := range expectedKeyIDs {
			go func(keyID string) {
				defer waitGroup.Done()
				<-barrier
				key, err := cache.ResolveKey(context.Background(), keyID)
				assert.Nil(key)
				assert.Equal(expectedError, err)
			}(keyID)
		}
	}

	close(barrier)
	waitGroup.Wait()

	mock.AssertExpectationsForObjects(t, resolver.Mock)
}

func TestMultiCacheUpdateKeys(t *testing.T) {
	assert := assert.New(t)

	resolver := &MockResolver{}
	expectedKeyIDs, expectedPairs := makeExpectedPairs(2)
	t.Logf("expectedKeyIDs: %s", expectedKeyIDs)

	for _, keyID := range expectedKeyIDs {
		resolver.On("ResolveKey", mock.Anything, keyID).Return(expectedPairs[keyID], nil).Twice()
	}

	cache := multiCache{
		basicCache{
			delegate: resolver,
		},
	}

	count, errors := cache.UpdateKeys(context.Background())
	assert.Equal(0, count)
	assert.Len(errors, 0)

	for _, keyID := range expectedKeyIDs {
		pair, err := cache.ResolveKey(context.Background(), keyID)
		assert.Equal(expectedPairs[keyID], pair)
		assert.Nil(err)
	}

	count, errors = cache.UpdateKeys(context.Background())
	assert.Equal(len(expectedKeyIDs), count)
	assert.Len(errors, 0)

	mock.AssertExpectationsForObjects(t, resolver.Mock)
	assertExpectationsForPairs(t, expectedPairs)
}

func TestMultiCacheUpdateKeysError(t *testing.T) {
	assert := assert.New(t)

	expectedError := errors.New("TestMultiCacheUpdateKeysError")
	expectedKeyIDs, _ := makeExpectedPairs(2)
	resolver := &MockResolver{}
	for _, keyID := range expectedKeyIDs {
		resolver.On("ResolveKey", mock.Anything, keyID).Return(nil, expectedError).Once()
	}

	cache := multiCache{
		basicCache{
			delegate: resolver,
		},
	}

	count, errors := cache.UpdateKeys(context.Background())
	assert.Equal(0, count)
	assert.Len(errors, 0)

	for _, keyID := range expectedKeyIDs {
		key, err := cache.ResolveKey(context.Background(), keyID)
		assert.Nil(key)
		assert.Equal(expectedError, err)
	}

	// UpdateKeys should still not do anything, because
	// nothing should be in the cache due to errors
	count, errors = cache.UpdateKeys(context.Background())
	assert.Equal(0, count)
	assert.Len(errors, 0)

	mock.AssertExpectationsForObjects(t, resolver.Mock)
}

func TestMultiCacheUpdateKeysSequence(t *testing.T) {
	assert := assert.New(t)

	const keyID = "TestMultiCacheUpdateKeysSequence"
	expectedError := errors.New("TestMultiCacheUpdateKeysSequence")
	oldPair := &MockPair{}
	newPair := &MockPair{}

	resolver := &MockResolver{}
	resolver.On("ResolveKey", mock.Anything, keyID).Return(oldPair, nil).Once()
	resolver.On("ResolveKey", mock.Anything, keyID).Return(nil, expectedError).Once()
	resolver.On("ResolveKey", mock.Anything, keyID).Return(newPair, nil).Once()

	cache := multiCache{
		basicCache{
			delegate: resolver,
		},
	}

	pair, err := cache.ResolveKey(context.Background(), keyID)
	assert.Equal(oldPair, pair)
	assert.Nil(err)

	// an error should leave the existing key alone
	count, errors := cache.UpdateKeys(context.Background())
	assert.Equal(1, count)
	assert.Equal([]error{expectedError}, errors)

	// the key should resolve to the old key from the cache
	pair, err = cache.ResolveKey(context.Background(), keyID)
	assert.Equal(oldPair, pair)
	assert.Nil(err)

	// again, this time the mock will succeed
	count, errors = cache.UpdateKeys(context.Background())
	assert.Equal(1, count)
	assert.Len(errors, 0)

	// resolving a key should show the new value now
	pair, err = cache.ResolveKey(context.Background(), keyID)
	assert.Equal(newPair, pair)
	assert.Nil(err)

	mock.AssertExpectationsForObjects(t, resolver.Mock, oldPair.Mock, newPair.Mock)
}
