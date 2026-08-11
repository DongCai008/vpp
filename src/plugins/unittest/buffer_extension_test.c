/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/buffer_funcs.h>

#define TEST(_cond, _comment, _args...)                                                            \
  do                                                                                               \
    {                                                                                              \
      if (!(_cond))                                                                                \
	return clib_error_return (0, _comment, ##_args);                                           \
    }                                                                                              \
  while (0)

typedef struct
{
  u32 magic;
} buffer_extension_test_data_t;

static u32 buffer_extension_test_init_count;
static u32 buffer_extension_test_alloc_count;
static u32 buffer_extension_test_free_count;

static void
buffer_extension_test_init (vlib_main_t *vm, vlib_buffer_t *b, void *data)
{
  buffer_extension_test_data_t *extension = data;

  (void) vm;
  (void) b;
  extension->magic = 0x12345678;
  buffer_extension_test_init_count++;
}

static void
buffer_extension_test_alloc (vlib_main_t *vm, u8 buffer_pool_index, u32 *buffers, u32 n_buffers,
			     vlib_buffer_extension_t *extension)
{
  (void) vm;
  (void) buffer_pool_index;
  (void) buffers;
  (void) extension;
  buffer_extension_test_alloc_count += n_buffers;
}

static void
buffer_extension_test_free (vlib_main_t *vm, u8 buffer_pool_index, u32 *buffers, u32 n_buffers,
			    vlib_buffer_extension_t *extension)
{
  (void) vm;
  (void) buffer_pool_index;
  (void) buffers;
  (void) extension;
  buffer_extension_test_free_count += n_buffers;
}

static vlib_buffer_extension_t buffer_extension_test_a = {
  .name = "unittest-buffer-extension-a",
  .size = sizeof (buffer_extension_test_data_t),
  .align = CLIB_CACHE_LINE_BYTES,
  .init = buffer_extension_test_init,
  .alloc = buffer_extension_test_alloc,
  .free = buffer_extension_test_free,
};

static vlib_buffer_extension_t buffer_extension_test_b = {
  .name = "unittest-buffer-extension-b",
  .size = CLIB_CACHE_LINE_BYTES,
  .align = 2 * CLIB_CACHE_LINE_BYTES,
};

static void __clib_constructor
buffer_extension_test_register (void)
{
  if (vlib_buffer_register_extension (&buffer_extension_test_a) ||
      vlib_buffer_register_extension (&buffer_extension_test_b))
    clib_panic ("failed to register unit-test buffer extensions");
}

static clib_error_t *
test_buffer_extensions (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  buffer_extension_test_data_t *a;
  void *b;
  u32 buffers[4];
  u32 n_buffers;
  u32 alloc_count;
  u32 free_count;
  uword i;

  (void) input;
  (void) cmd;

  TEST (buffer_extension_test_init_count != 0, "buffer extension initializers were not called");

  alloc_count = buffer_extension_test_alloc_count;
  n_buffers = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
  TEST (n_buffers == ARRAY_LEN (buffers), "failed to allocate test buffers");
  TEST (buffer_extension_test_alloc_count == alloc_count + n_buffers,
	"buffer allocation observer was not called");

  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *vb = vlib_get_buffer (vm, buffers[i]);

      a = vlib_buffer_get_extension (vb, &buffer_extension_test_a);
      b = vlib_buffer_get_extension (vb, &buffer_extension_test_b);
      TEST (pointer_to_uword (a) % buffer_extension_test_a.align == 0,
	    "first extension is not aligned");
      TEST (pointer_to_uword (b) % buffer_extension_test_b.align == 0,
	    "second extension is not aligned");
      TEST ((u8 *) a + buffer_extension_test_a.size <= (u8 *) vb,
	    "first extension overlaps vlib buffer");
      TEST ((u8 *) b + buffer_extension_test_b.size <= (u8 *) vb,
	    "second extension overlaps vlib buffer");
      TEST (a->magic == 0x12345678, "extension initializer state is invalid");
    }

  free_count = buffer_extension_test_free_count;
  vlib_buffer_free (vm, buffers, n_buffers);
  TEST (buffer_extension_test_free_count == free_count + n_buffers,
	"buffer free observer was not called");

  vlib_cli_output (vm, "buffer extension test passed");
  return 0;
}

VLIB_CLI_COMMAND (test_buffer_extensions_command, static) = {
  .path = "test buffer extensions",
  .short_help = "test buffer extensions",
  .function = test_buffer_extensions,
};
