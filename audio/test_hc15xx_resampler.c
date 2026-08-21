// SPDX-License-Identifier: MIT
#include "hc15xx_resampler.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static size_t reference_process(struct hc15xx_resampler *state,
	const int16_t *stereo, size_t frames, int16_t *mono, size_t capacity)
{
	size_t input;
	size_t produced = 0;

	for (input = 0; input < frames; ++input) {
		int32_t current = ((int32_t)stereo[input * 2] +
			(int32_t)stereo[input * 2 + 1]) / 2;
		uint32_t old_phase;
		uint64_t advanced;
		uint64_t outputs;
		uint64_t output_index;

		if (!state->have_previous) {
			if (produced >= capacity)
				break;
			state->previous = current;
			state->have_previous = 1;
			mono[produced++] = (int16_t)current;
			continue;
		}
		old_phase = state->phase;
		advanced = (uint64_t)old_phase + state->output_rate;
		outputs = advanced / state->input_rate;
		if (outputs > (uint64_t)capacity - produced)
			break;
		for (output_index = 0; output_index < outputs; ++output_index) {
			uint64_t fraction = (uint64_t)state->input_rate - old_phase +
				output_index * state->input_rate;
			int64_t delta = (int64_t)current - state->previous;

			mono[produced++] = (int16_t)(state->previous +
				delta * (int64_t)fraction / state->output_rate);
		}
		state->phase = (uint32_t)(advanced - outputs * state->input_rate);
		state->previous = current;
	}
	return produced;
}

static void check_bit_exact(uint32_t input_rate, uint32_t output_rate)
{
	struct hc15xx_resampler optimized;
	struct hc15xx_resampler reference;
	int16_t stereo[257 * 2];
	int16_t optimized_output[1024];
	int16_t reference_output[1024];
	size_t optimized_count;
	size_t reference_count;
	unsigned i;

	for (i = 0; i < 257; ++i) {
		stereo[i * 2] = (int16_t)((i * 811u) ^ 0x8000u);
		stereo[i * 2 + 1] = (int16_t)((i * 4051u) ^ 0x5555u);
	}
	assert(hc15xx_resampler_init(&optimized, input_rate, output_rate) == 0);
	reference = optimized;
	optimized_count = hc15xx_resampler_process_stereo_s16(&optimized,
		stereo, 257, optimized_output, 1024);
	reference_count = reference_process(&reference, stereo, 257,
		reference_output, 1024);
	assert(optimized_count == reference_count);
	assert(!memcmp(optimized_output, reference_output,
		optimized_count * sizeof(*optimized_output)));
	assert(optimized.phase == reference.phase);
	assert(optimized.previous == reference.previous);
	assert(optimized.have_previous == reference.have_previous);
}

int main(void)
{
	struct hc15xx_resampler state;
	struct hc15xx_resampler batch_state;
	int16_t output;
	int16_t stereo[32768 * 2];
	int16_t batch_output[32768];
	unsigned produced = 0;
	unsigned i;

	assert(hc15xx_resampler_init(&state, 32000, 32000) == 0);
	for (i = 0; i < 100; i++) {
		assert(hc15xx_resampler_push_stereo_s16(&state,
			(int16_t)i, (int16_t)i, &output) == 1);
		assert(output == (int16_t)i);
	}

	assert(hc15xx_resampler_init(&state, 32768, 32000) == 0);
	for (i = 0; i < 32768; i++) {
		int emitted = hc15xx_resampler_push_stereo_s16(&state,
			(int16_t)(i & 0x7fff), (int16_t)(i & 0x7fff), &output);

		assert(emitted >= 0);
		produced += (unsigned)emitted;
	}
	assert(produced == 32000);
	assert(hc15xx_resampler_init(&batch_state, 32768, 32000) == 0);
	for (i = 0; i < 32768; ++i) {
		stereo[i * 2] = (int16_t)(i & 0x7fff);
		stereo[i * 2 + 1] = (int16_t)(i & 0x7fff);
	}
	assert(hc15xx_resampler_process_stereo_s16(&batch_state, stereo,
		32768, batch_output, 32768) == 32000);
	assert(hc15xx_resampler_set_output_rate(&batch_state, 32256) == 0);
	assert(batch_state.output_rate == 32256);
	assert(hc15xx_resampler_set_output_rate(&batch_state, 32769) == 0);
	assert(hc15xx_resampler_process_stereo_s16(&batch_state, stereo,
		1, batch_output, 0) == 0);
	assert(hc15xx_resampler_init(&state, 16000, 32000) == 0);
	assert(hc15xx_resampler_process_stereo_s16(&state, stereo,
		16000, batch_output, 32768) == 31999);
	check_bit_exact(44100, 32000);
	check_bit_exact(32000, 32000);
	check_bit_exact(22050, 48000);
	check_bit_exact(65535, 65534);
	check_bit_exact(65534, 65535);
	check_bit_exact(96000, 32000);
	puts("hc15xx resampler tests: PASS");
	return 0;
}
