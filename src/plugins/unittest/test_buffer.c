/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/buffer_funcs.h>
#include <vnet/ip/ip.h>

#define TEST_I(_cond, _comment, _args...)                                     \
  ({                                                                          \
    int _evald = (0 == (_cond));                                              \
    if (_evald)                                                               \
      {                                                                       \
	fformat (stderr, "FAIL:%d: " _comment "\n", __LINE__, ##_args);       \
      }                                                                       \
    else                                                                      \
      {                                                                       \
	fformat (stderr, "PASS:%d: " _comment "\n", __LINE__, ##_args);       \
      }                                                                       \
    _evald;                                                                   \
  })

#define TEST(_cond, _comment, _args...)                                       \
  {                                                                           \
    if (TEST_I (_cond, _comment, ##_args))                                    \
      {                                                                       \
	goto err;                                                             \
      }                                                                       \
  }

typedef struct
{
  i16 current_data;
  u16 current_length;
  u8 ref_count;
} chained_buffer_template_t;

static int
build_chain (vlib_main_t *vm, const chained_buffer_template_t *tmpl, u32 n,
	     clib_random_buffer_t *randbuf, u8 **rand, vlib_buffer_t **b_,
	     u32 *bi_)
{
  vlib_buffer_t *bufs[2 * VLIB_BUFFER_LINEARIZE_MAX], **b = bufs;
  u32 bis[2 * VLIB_BUFFER_LINEARIZE_MAX + 1], *bi = bis;
  u32 n_alloc;

  if (rand)
    vec_reset_length (*rand);

  ASSERT (n <= ARRAY_LEN (bufs));
  n_alloc = vlib_buffer_alloc (vm, bi, n);
  if (n_alloc != n)
    {
      vlib_buffer_free (vm, bi, n_alloc);
      return 0;
    }

  vlib_get_buffers (vm, bis, bufs, n);

  while (n > 0)
    {
      b[0]->next_buffer = bi[1];
      b[0]->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b[0]->current_data = tmpl->current_data;
      b[0]->current_length = tmpl->current_length;
      b[0]->ref_count = 0xff == tmpl->ref_count ? 1 : tmpl->ref_count;

      if (rand)
	{
	  const u16 len = b[0]->current_length;
	  if (len)
	    {
	      vec_add (*rand, clib_random_buffer_get_data (randbuf, len), len);
	      void *dst = vlib_buffer_get_current (b[0]);
	      const void *src =
		vec_elt_at_index (*rand, vec_len (*rand) - len);
	      clib_memcpy_fast (dst, src, len);
	    }
	}

      b++;
      bi++;
      tmpl++;
      n--;
    }

  b[-1]->flags &= ~VLIB_BUFFER_NEXT_PRESENT;

  *b_ = bufs[0];
  *bi_ = bis[0];
  return 1;
}

static int
check_chain (vlib_main_t *vm, vlib_buffer_t *b, const u8 *rand)
{
  int len_chain = vlib_buffer_length_in_chain (vm, b);
  int len;

  /* check for data corruption */
  if (clib_memcmp (vlib_buffer_get_current (b), vec_elt_at_index (rand, 0),
		   b->current_length))
    return 0;
  len = b->current_length;
  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      b = vlib_get_buffer (vm, b->next_buffer);
      if (clib_memcmp (vlib_buffer_get_current (b),
		       vec_elt_at_index (rand, len), b->current_length))
	return 0;
      len += b->current_length;
    }

  /* check for data truncation */
  if (len != vec_len (rand))
    return 0;

  /* check total length update is correct */
  if (len != len_chain)
    return 0;

  return 1;
}

static int
test_chain (vlib_main_t *vm, const chained_buffer_template_t *tmpl,
	    const u32 n, const int clone_off, clib_random_buffer_t *randbuf,
	    u8 **rand)
{
  vlib_buffer_t *b;
  u32 bi[2];
  int ret = 0;

  if (!build_chain (vm, tmpl, n, randbuf, rand, &b, bi))
    goto err0;

  if (clone_off)
    {
      if (2 != vlib_buffer_clone (vm, bi[0], bi, 2, clone_off))
	goto err1;
      b = vlib_get_buffer (vm, bi[0]);
    }

  if (!(ret = vlib_buffer_chain_linearize (vm, b)))
    goto err2;

  if (!check_chain (vm, b, *rand))
    {
      ret = 0;
      goto err2;
    }

err2:
  if (clone_off)
    vlib_buffer_free_one (vm, bi[1]);
err1:
  vlib_buffer_free_one (vm, bi[0]);
err0:
  return ret;
}

static int
chain_view_test (vlib_main_t *vm)
{
  const chained_buffer_template_t tmpl[] = {
    { 11, 3, 1 },
    { -7, 5, 1 },
    { 23, 7, 1 },
  };
  vlib_buffer_chain_physical_t physical_iterator;
  vlib_buffer_chain_physical_segment_t physical_segment;
  vlib_buffer_chain_view_t view_iterator;
  vlib_buffer_chain_view_segment_t view_segment;
  clib_random_buffer_t randbuf;
  vlib_buffer_t *b = 0;
  u8 *contents = 0;
  u8 *rand = 0;
  u8 prefix[9];
  u32 bi;
  uword logical_length = 0;
  uword physical_length = 0;
  uword n_logical = 0;
  uword n_physical = 0;
  int ret = 0;

  clib_random_buffer_init (&randbuf, 0);
  if (!build_chain (vm, tmpl, ARRAY_LEN (tmpl), &randbuf, &rand, &b, &bi))
    goto err;

  b->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
  vlib_buffer_chain_physical_init (&physical_iterator, vm, b);
  vlib_buffer_chain_view_init (&view_iterator, vm, b, 0);
  while (vlib_buffer_chain_view_next (&view_iterator, &view_segment))
    {
      TEST (vlib_buffer_chain_physical_next (&physical_iterator, &physical_segment),
	    "physical iterator covers each logical segment");
      TEST (view_segment.buffer == physical_segment.buffer,
	    "logical and physical iterators select the same buffer");
      TEST (view_segment.data_skip == 0, "ordinary buffer-chain view has no data skip");
      TEST (view_segment.data == vlib_buffer_get_current (physical_segment.buffer),
	    "logical range starts at the physical current data");
      TEST (view_segment.data_length == physical_segment.buffer->current_length,
	    "logical range covers the physical segment");

      logical_length += view_segment.data_length;
      physical_length += physical_segment.buffer->current_length;
      n_logical++;
      n_physical++;
    }

  TEST (!vlib_buffer_chain_physical_next (&physical_iterator, &physical_segment),
	"physical iterator ends with the logical iterator");
  TEST (n_logical == ARRAY_LEN (tmpl) && n_physical == ARRAY_LEN (tmpl),
	"iterators report all chain segments");
  TEST (logical_length == physical_length,
	"logical and physical lengths agree for an ordinary chain");
  TEST (logical_length == vlib_buffer_chain_view_length (vm, b, 0),
	"view aggregate length matches the iterator ranges");
  TEST (logical_length == vlib_buffer_length_in_chain (vm, b),
	"view aggregate length matches VLIB chain length");

  vec_validate (contents, logical_length - 1);
  TEST (logical_length == vlib_buffer_contents (vm, bi, contents),
	"contents reader returns the logical chain length");
  TEST (clib_memcmp (contents, rand, logical_length) == 0,
	"contents reader copies all logical ranges");
  TEST (vlib_buffer_chain_view_copy (vm, b, prefix, sizeof (prefix), 0) == sizeof (prefix),
	"bounded copy returns its logical prefix length");
  TEST (clib_memcmp (prefix, rand, sizeof (prefix)) == 0,
	"bounded copy preserves the ordinary-chain prefix");

  ret = 1;
err:
  if (b)
    vlib_buffer_free_one (vm, bi);
  vec_free (contents);
  vec_free (rand);
  clib_random_buffer_free (&randbuf);
  return ret;
}

static clib_error_t *
test_chain_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!chain_view_test (vm))
    return clib_error_return (0, "buffer-chain view test failed");

  return 0;
}

VLIB_CLI_COMMAND (test_chain_view_command, static) = {
  .path = "test buffer-chain-view",
  .short_help = "test buffer-chain-view",
  .function = test_chain_view_fn,
};

static int
shared_view_mutation_test (vlib_main_t *vm)
{
  vlib_buffer_t *copy;
  vlib_buffer_t *descriptor;
  vlib_buffer_t *root;
  vlib_buffer_t *tail;
  u32 buffers[3];
  u32 mutable_index;
  u32 root_index;
  u32 saved_next;
  u32 i;
  int ret = 0;

  if (vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers)) != ARRAY_LEN (buffers))
    return 0;

  mutable_index = buffers[2];
  root = vlib_get_buffer (vm, buffers[0]);
  tail = vlib_get_buffer (vm, buffers[1]);
  descriptor = vlib_get_buffer (vm, buffers[2]);
  root->current_data = 3;
  root->current_length = 29;
  root->next_buffer = buffers[1];
  root->flags |= VLIB_BUFFER_NEXT_PRESENT | VLIB_BUFFER_IS_TRACED;
  root->flow_id = 0x12345678;
  root->error = 19;
  root->current_config_index = 37;
  root->trace_handle = 0xabcdef01;
  tail->current_data = -4;
  tail->current_length = 17;
  for (i = 0; i < root->current_length; i++)
    ((u8 *) vlib_buffer_get_current (root))[i] = i;
  for (i = 0; i < tail->current_length; i++)
    ((u8 *) vlib_buffer_get_current (tail))[i] = root->current_length + i;
  for (i = 0; i < ARRAY_LEN (root->opaque); i++)
    {
      root->opaque[i] = 0x1000 + i;
      tail->opaque[i] = 0x2000 + i;
    }
  for (i = 0; i < ARRAY_LEN (root->opaque2); i++)
    {
      root->opaque2[i] = 0x3000 + i;
      tail->opaque2[i] = 0x4000 + i;
    }

  descriptor->flow_id = 0x87654321;
  descriptor->error = 53;
  descriptor->current_config_index = 61;
  clib_memset (descriptor->opaque, 0xa5, sizeof (descriptor->opaque));
  clib_memset (descriptor->opaque2, 0x5a, sizeof (descriptor->opaque2));
  TEST (vlib_buffer_shared_view_attach (vm, buffers[2], buffers[0]) == 0,
	"shared-view descriptor attachment succeeds");
  TEST (vlib_buffer_shared_view_is_shared (root) &&
	  vlib_buffer_shared_view_is_shared (descriptor) &&
	  (root->flags & VLIB_BUFFER_SHARED_VIEW_ROOT) &&
	  (descriptor->flags & VLIB_BUFFER_SHARED_VIEW_DESCRIPTOR) && root->ref_count == 2 &&
	  tail->ref_count == 2,
	"shared-view attachment publishes the generic identity and references");
  TEST (vlib_buffer_shared_view_root (vm, buffers[2], &root_index) == 0 && root_index == buffers[0],
	"shared-view root resolution returns the canonical root");

  saved_next = descriptor->next_buffer;
  descriptor->next_buffer = buffers[1];
  mutable_index = buffers[2];
  TEST (vlib_buffer_shared_view_make_writable (vm, &mutable_index) != 0 &&
	  mutable_index == buffers[2] && root->ref_count == 2 && tail->ref_count == 2,
	"failed shared-view validation leaves the caller view and references unchanged");
  descriptor->next_buffer = saved_next;

  mutable_index = buffers[2];
  TEST (vlib_buffer_shared_view_make_writable (vm, &mutable_index) == 0 &&
	  mutable_index != buffers[2] && root->ref_count == 1 && tail->ref_count == 1,
	"shared-view mutation publishes a replacement and releases one view");
  copy = vlib_get_buffer (vm, mutable_index);
  TEST (!vlib_buffer_shared_view_is_shared (copy) && copy->flow_id == root->flow_id &&
	  copy->error == root->error && copy->current_config_index == root->current_config_index &&
	  copy->trace_handle == root->trace_handle &&
	  clib_memcmp (copy->opaque, root->opaque, sizeof (root->opaque)) == 0 &&
	  clib_memcmp (copy->opaque2, root->opaque2, sizeof (root->opaque2)) == 0 &&
	  clib_memcmp (vlib_buffer_get_current (copy), vlib_buffer_get_current (root),
		       root->current_length) == 0,
	"shared-view mutation copies canonical root metadata and data");
  copy = vlib_get_buffer (vm, copy->next_buffer);
  TEST (!vlib_buffer_shared_view_is_shared (copy) &&
	  clib_memcmp (copy->opaque, tail->opaque, sizeof (tail->opaque)) == 0 &&
	  clib_memcmp (copy->opaque2, tail->opaque2, sizeof (tail->opaque2)) == 0 &&
	  clib_memcmp (vlib_buffer_get_current (copy), vlib_buffer_get_current (tail),
		       tail->current_length) == 0,
	"shared-view mutation deep-copies tail opaque metadata and data");

  TEST (vlib_buffer_shared_view_make_writable (vm, &mutable_index) == 0,
	"ordinary replacement is a mutation-boundary no-op");
  ret = 1;
err:
  vlib_buffer_free_one (vm, mutable_index);
  vlib_buffer_free_one (vm, buffers[0]);
  return ret;
}

static clib_error_t *
test_shared_view_mutation_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!shared_view_mutation_test (vm))
    return clib_error_return (0, "buffer shared-view mutation test failed");

  return 0;
}

VLIB_CLI_COMMAND (test_shared_view_mutation_command, static) = {
  .path = "test buffer-shared-view-mutation",
  .short_help = "test buffer-shared-view-mutation",
  .function = test_shared_view_mutation_fn,
};

static ip_csum_t
checksum_chain_raw (vlib_main_t *vm, vlib_buffer_t *first_buffer, u32 first_buffer_offset,
		    u32 n_bytes_to_checksum, ip_csum_t sum)
{
  vlib_buffer_t *buffer = first_buffer;
  u32 n_bytes_left = n_bytes_to_checksum;
  u32 n;

  n = clib_min (n_bytes_left, buffer->current_length - first_buffer_offset);
  sum = ip_incremental_checksum (sum, vlib_buffer_get_current (buffer) + first_buffer_offset, n);
  if (PREDICT_FALSE (buffer->flags & VLIB_BUFFER_NEXT_PRESENT))
    {
      while (1)
	{
	  n_bytes_left -= n;
	  if (n_bytes_left == 0)
	    break;
	  buffer = vlib_get_buffer (vm, buffer->next_buffer);
	  n = clib_min (n_bytes_left, buffer->current_length);
	  sum = ip_incremental_checksum (sum, vlib_buffer_get_current (buffer), n);
	}
    }

  return sum;
}

static int
checksum_chain_view_test (vlib_main_t *vm)
{
  const chained_buffer_template_t tmpl[] = {
    { 0, 31, 1 },
    { 0, 23, 1 },
    { 0, 17, 1 },
  };
  ip4_header_t *ip4;
  vlib_buffer_t *b = 0;
  u8 *contents = 0;
  uword length;
  uword offset = 0;
  u32 bi;
  ip_csum_t actual;
  ip_csum_t expected;
  u16 actual_l4;
  u16 expected_l4;
  int ret = 0;

  if (!build_chain (vm, tmpl, ARRAY_LEN (tmpl), 0, 0, &b, &bi))
    goto err;

  length = vlib_buffer_length_in_chain (vm, b);
  for (vlib_buffer_t *segment = b; segment; segment = vlib_get_next_buffer (vm, segment))
    {
      u8 *data = vlib_buffer_get_current (segment);

      for (uword i = 0; i < segment->current_length; i++)
	data[i] = offset + i;
      offset += segment->current_length;
    }
  ip4 = vlib_buffer_get_current (b);
  ip4->ip_version_and_header_length = 0x45;
  ip4->length = clib_host_to_net_u16 (length);
  ip4->protocol = IP_PROTOCOL_TCP;
  ip4->src_address.as_u32 = clib_host_to_net_u32 (0xc0000201);
  ip4->dst_address.as_u32 = clib_host_to_net_u32 (0xc6336402);

  vec_validate (contents, length - 1);
  TEST (vlib_buffer_contents (vm, bi, contents) == length,
	"checksum test copies the ordinary chain view");

  expected = checksum_chain_raw (vm, b, 7, length - 7, 0);
  actual = ip_incremental_checksum_buffer (vm, b, 7, length - 7, 0);
  TEST (actual == expected, "incremental checksum matches the raw chain walk");

  expected = clib_host_to_net_u32 ((length - sizeof (*ip4)) + (IP_PROTOCOL_TCP << 16));
  expected = ip_csum_with_carry (expected, clib_mem_unaligned (&ip4->src_address, u64));
  expected = ip_incremental_checksum (expected, contents + sizeof (*ip4), length - sizeof (*ip4));
  expected_l4 = ~ip_csum_fold (expected);
  actual_l4 = ip4_tcp_udp_compute_checksum (vm, b, ip4);
  TEST (actual_l4 == expected_l4, "L4 checksum matches contiguous ordinary chain data");

  ret = 1;
err:
  if (b)
    vlib_buffer_free_one (vm, bi);
  vec_free (contents);
  return ret;
}

static clib_error_t *
test_checksum_chain_view_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!checksum_chain_view_test (vm))
    return clib_error_return (0, "checksum chain-view test failed");

  return 0;
}

VLIB_CLI_COMMAND (test_checksum_chain_view_command, static) = {
  .path = "test checksum-chain-view",
  .short_help = "test checksum-chain-view",
  .function = test_checksum_chain_view_fn,
};

static int
linearize_test (vlib_main_t *vm)
{
  chained_buffer_template_t tmpl[VLIB_BUFFER_LINEARIZE_MAX];
  clib_random_buffer_t randbuf;
  u32 data_size = vlib_buffer_get_default_data_size (vm);
  u8 *rand = 0;
  int ret = 0;
  int i;

  clib_random_buffer_init (&randbuf, 0);

  clib_memset (tmpl, 0xff, sizeof (tmpl));
  for (i = 0; i < 2; i++)
    {
      tmpl[i].current_data = -14;
      tmpl[i].current_length = 14 + data_size;
    }
  TEST (2 == test_chain (vm, tmpl, 2, 0, &randbuf, &rand),
	"linearize chain with negative current data");

  clib_memset (tmpl, 0xff, sizeof (tmpl));
  tmpl[0].current_data = 12;
  tmpl[0].current_length = data_size - 12;
  tmpl[1].current_data = 0;
  tmpl[1].current_length = 0;
  TEST (1 == test_chain (vm, tmpl, 2, 0, &randbuf, &rand),
	"linearize chain with empty next");

  clib_memset (tmpl, 0xff, sizeof (tmpl));
  tmpl[0].current_data = 0;
  tmpl[0].current_length = data_size - 17;
  tmpl[1].current_data = -5;
  tmpl[1].current_length = 3;
  tmpl[2].current_data = 17;
  tmpl[2].current_length = 9;
  tmpl[3].current_data = 3;
  tmpl[3].current_length = 5;
  TEST (1 == test_chain (vm, tmpl, 4, 0, &randbuf, &rand),
	"linearize chain into a single buffer");

  clib_memset (tmpl, 0xff, sizeof (tmpl));
  tmpl[0].current_data = 0;
  tmpl[0].current_length = data_size - 2;
  tmpl[1].current_data = -VLIB_BUFFER_PRE_DATA_SIZE;
  tmpl[1].current_length = 20;
  tmpl[2].current_data = data_size - 10;
  tmpl[2].current_length = 10;
  tmpl[3].current_data = 0;
  tmpl[3].current_length = data_size;
  TEST (2 == test_chain (vm, tmpl, 4, data_size - 1, &randbuf, &rand),
	"linearize cloned chain");

  clib_memset (tmpl, 0xff, sizeof (tmpl));
  for (i = 0; i < 100; i++)
    {
      u8 *r = clib_random_buffer_get_data (&randbuf, 1);
      int n = clib_max (r[0] % ARRAY_LEN (tmpl), 1);
      int j;
      for (j = 0; j < n; j++)
	{
	  r = clib_random_buffer_get_data (&randbuf, 3);
	  i16 current_data = (i16) r[0] - VLIB_BUFFER_PRE_DATA_SIZE;
	  u16 current_length = *(u16 *) (r + 1) % (data_size - current_data);
	  tmpl[j].current_data = current_data;
	  tmpl[j].current_length = current_length;
	}
      r = clib_random_buffer_get_data (&randbuf, 1);
      TEST (
	test_chain (vm, tmpl, n, r[0] > 250 ? r[0] % 128 : 0, &randbuf, &rand),
	"linearize random chain %d", i);
    }

  ret = 1;
err:
  clib_random_buffer_free (&randbuf);
  vec_free (rand);
  return ret;
}

static clib_error_t *
test_linearize_fn (vlib_main_t * vm, unformat_input_t * input,
		   vlib_cli_command_t * cmd)
{

  if (!linearize_test (vm))
    {
      return clib_error_return (0, "linearize test failed");
    }

  return 0;
}

VLIB_CLI_COMMAND (test_linearize_command, static) =
{
  .path = "test chained-buffer-linearization",
  .short_help = "test chained-buffer-linearization",
  .function = test_linearize_fn,
};

static clib_error_t *
test_linearize_speed_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  /* typical 9000-bytes TCP jumbo frames */
  const chained_buffer_template_t tmpl[5] = { { 14, 2034, 1 },
					      { 0, 2048, 1 },
					      { 0, 2048, 1 },
					      { 0, 2048, 1 },
					      { 0, 808, 1 } };
  int i, j;

  for (i = 0; i < 10; i++)
    {
      u64 tot = 0;
      for (j = 0; j < 100000; j++)
	{
	  vlib_buffer_t *b;
	  u32 bi;

	  if (!build_chain (vm, tmpl, 5, 0, 0, &b, &bi))
	    return clib_error_create ("build_chain() failed");

	  CLIB_COMPILER_BARRIER ();
	  u64 start = clib_cpu_time_now ();
	  CLIB_COMPILER_BARRIER ();

	  vlib_buffer_chain_linearize (vm, b);

	  CLIB_COMPILER_BARRIER ();
	  tot += clib_cpu_time_now () - start;
	  CLIB_COMPILER_BARRIER ();

	  vlib_buffer_free_one (vm, bi);
	}
      vlib_cli_output (vm, "%.03f ticks/call", (f64) tot / j);
    }

  return 0;
}

VLIB_CLI_COMMAND (test_linearize_speed_command, static) = {
  .path = "test chained-buffer-linearization speed",
  .short_help = "test chained-buffer-linearization speed",
  .function = test_linearize_speed_fn,
};
