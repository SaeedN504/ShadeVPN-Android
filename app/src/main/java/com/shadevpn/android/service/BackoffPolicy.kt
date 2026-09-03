package com.shadevpn.android.service

import kotlin.random.Random

/**
 * Exponential backoff with full jitter for reconnect attempts.
 * Pure JVM logic — unit-testable without Android.
 *
 * Delay sequence: base * 2^attempt, clamped to [base, maxDelay], then
 * randomized uniformly in [0, computed] (full jitter) to avoid retry
 * storms when many clients reconnect at once.
 */
class BackoffPolicy(
    private val baseMs: Long = DEFAULT_BASE_MS,
    private val maxDelayMs: Long = DEFAULT_MAX_DELAY_MS,
    private val maxAttempts: Int = DEFAULT_MAX_ATTEMPTS,
    private val random: Random = Random.Default
) {
    private var attempt = 0

    /** Next delay in ms, or null when the retry budget is exhausted. */
    fun nextDelayMs(): Long? {
        if (attempt >= maxAttempts) return null
        // Shift is capped so baseMs * 2^attempt cannot overflow Long for
        // pathological base values.
        val exp = baseMs * (1L shl attempt.coerceAtMost(30))
        val capped = exp.coerceAtMost(maxDelayMs).coerceAtLeast(0)
        attempt++
        // nextDouble() is in [0,1), so this is uniform in [0, capped) and
        // cannot overflow like nextLong() * capped would.
        return if (capped <= 0) 0 else (random.nextDouble() * capped).toLong()
    }

    /** Number of attempts consumed so far. */
    fun attemptsSoFar(): Int = attempt

    /** True while another retry is permitted. */
    fun canRetry(): Boolean = attempt < maxAttempts

    fun reset() {
        attempt = 0
    }

    companion object {
        const val DEFAULT_BASE_MS = 500L
        const val DEFAULT_MAX_DELAY_MS = 15_000L
        const val DEFAULT_MAX_ATTEMPTS = 5
    }
}
