package com.shadevpn.android.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

class BackoffPolicyTest {

    @Test
    fun delays_grow_exponentially_and_are_capped() {
        // Seed zero: deterministic sequence across JVMs (LCM64 seeded).
        val policy = BackoffPolicy(baseMs = 100, maxDelayMs = 1_000, maxAttempts = 10, random = Random(0))
        val delays = generateSequence { policy.nextDelayMs() }.takeWhile { it != null }.map { it!! }.toList()
        assertEquals(10, delays.size)
        assertTrue("delays must never exceed the cap: $delays", delays.all { it in 0..1_000 })
        // Full jitter means every delay is <= its uncapped exponential value.
        val uncapped = listOf(100L, 200, 400, 800, 1000, 1000, 1000, 1000, 1000, 1000)
        assertTrue(delays.zip(uncapped).all { (d, u) -> d <= u })
    }

    @Test
    fun retry_budget_exhausts_to_null() {
        val policy = BackoffPolicy(maxAttempts = 3)
        repeat(3) { policy.nextDelayMs() }
        assertNull(policy.nextDelayMs())
        assertFalse(policy.canRetry())
        assertEquals(3, policy.attemptsSoFar())
    }

    @Test
    fun reset_restores_budget() {
        val policy = BackoffPolicy(maxAttempts = 2)
        repeat(2) { policy.nextDelayMs() }
        assertFalse(policy.canRetry())
        policy.reset()
        assertTrue(policy.canRetry())
        assertEquals(0, policy.attemptsSoFar())
    }

    @Test
    fun single_attempt_delay_never_exceeds_base() {
        val policy = BackoffPolicy(baseMs = 250, maxDelayMs = 60_000, maxAttempts = 1, random = Random(42))
        val d = policy.nextDelayMs()!!
        assertTrue("jitter delay $d must be < base 250", d in 0..250)
    }

    @Test
    fun zero_base_yields_zero_delay() {
        val policy = BackoffPolicy(baseMs = 0, maxDelayMs = 100, maxAttempts = 2)
        assertEquals(0L, policy.nextDelayMs())
    }
}
