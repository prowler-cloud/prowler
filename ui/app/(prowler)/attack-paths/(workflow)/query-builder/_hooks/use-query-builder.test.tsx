import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  CUSTOM_ATTACK_PATH_QUERY_MAX_LENGTH,
  CUSTOM_ATTACK_PATH_QUERY_READ_ONLY_ERROR_MESSAGE,
} from "@/lib/attack-paths/custom-query";
import type { AttackPathQuery } from "@/types/attack-paths";
import { ATTACK_PATH_QUERY_IDS } from "@/types/attack-paths";

import { useQueryBuilder } from "./use-query-builder";

const mockQueries: AttackPathQuery[] = [
  {
    type: "attack-paths-scans",
    id: "query-with-parameters",
    attributes: {
      name: "Query With Parameters",
      short_description: "Requires a principal ARN",
      description: "Returns paths for a principal",
      provider: "aws",
      attribution: null,
      parameters: [
        {
          name: "principal_arn",
          label: "Principal ARN",
          data_type: "string",
          description: "Principal to analyze",
          required: true,
        },
      ],
    },
  },
  {
    type: "attack-paths-scans",
    id: "query-without-parameters",
    attributes: {
      name: "Query Without Parameters",
      short_description: "Returns all privileged paths",
      description: "Returns all privileged paths",
      provider: "aws",
      attribution: null,
      parameters: [],
    },
  },
  {
    type: "attack-paths-scans",
    id: ATTACK_PATH_QUERY_IDS.CUSTOM,
    attributes: {
      name: "Custom openCypher query",
      short_description: "Write your own query",
      description: "Run a custom query against the graph.",
      provider: "aws",
      attribution: null,
      parameters: [
        {
          name: "query",
          label: "openCypher",
          data_type: "string",
          description: "",
          required: true,
          input_type: "textarea",
        },
      ],
    },
  },
];

describe("useQueryBuilder", () => {
  it("drops stale parameter values when switching to a query without parameters", async () => {
    // Given
    const { result } = renderHook(() => useQueryBuilder(mockQueries));

    act(() => {
      result.current.handleQueryChange("query-with-parameters");
    });

    await waitFor(() => {
      expect(result.current.selectedQueryData?.id).toBe(
        "query-with-parameters",
      );
    });

    act(() => {
      result.current.form.setValue(
        "principal_arn",
        "arn:aws:iam::123:user/alex",
      );
    });

    expect(result.current.getQueryParameters()).toEqual({
      principal_arn: "arn:aws:iam::123:user/alex",
    });

    // When
    act(() => {
      result.current.handleQueryChange("query-without-parameters");
    });

    // Then
    expect(result.current.selectedQueryData?.id).toBe(
      "query-without-parameters",
    );
    expect(result.current.getQueryParameters()).toBeUndefined();
  });

  it("rejects whitespace-only custom queries before execution", async () => {
    // Given
    const { result } = renderHook(() => useQueryBuilder(mockQueries));

    act(() => {
      result.current.handleQueryChange(ATTACK_PATH_QUERY_IDS.CUSTOM);
    });

    await waitFor(() => {
      expect(result.current.selectedQueryData?.id).toBe(
        ATTACK_PATH_QUERY_IDS.CUSTOM,
      );
    });

    act(() => {
      result.current.form.setValue("query", "   ");
    });

    // When
    let isValid = true;
    await act(async () => {
      isValid = await result.current.form.trigger("query");
    });

    // Then
    expect(isValid).toBe(false);
    expect(result.current.form.getFieldState("query").error?.message).toBe(
      "Custom query cannot be empty",
    );
  });

  it("rejects custom queries longer than the supported limit", async () => {
    // Given
    const { result } = renderHook(() => useQueryBuilder(mockQueries));

    act(() => {
      result.current.handleQueryChange(ATTACK_PATH_QUERY_IDS.CUSTOM);
    });

    await waitFor(() => {
      expect(result.current.selectedQueryData?.id).toBe(
        ATTACK_PATH_QUERY_IDS.CUSTOM,
      );
    });

    act(() => {
      result.current.form.setValue(
        "query",
        "x".repeat(CUSTOM_ATTACK_PATH_QUERY_MAX_LENGTH + 1),
      );
    });

    // When
    let isValid = true;
    await act(async () => {
      isValid = await result.current.form.trigger("query");
    });

    // Then
    expect(isValid).toBe(false);
    expect(result.current.form.getFieldState("query").error?.message).toBe(
      `Custom query must be ${CUSTOM_ATTACK_PATH_QUERY_MAX_LENGTH} characters or fewer`,
    );
  });

  it("rejects custom queries containing write operations", async () => {
    // Given
    const { result } = renderHook(() => useQueryBuilder(mockQueries));

    act(() => {
      result.current.handleQueryChange(ATTACK_PATH_QUERY_IDS.CUSTOM);
    });

    await waitFor(() => {
      expect(result.current.selectedQueryData?.id).toBe(
        ATTACK_PATH_QUERY_IDS.CUSTOM,
      );
    });

    act(() => {
      result.current.form.setValue("query", "CREATE (n:Test) RETURN n");
    });

    // When
    let isValid = true;
    await act(async () => {
      isValid = await result.current.form.trigger("query");
    });

    // Then
    expect(isValid).toBe(false);
    expect(result.current.form.getFieldState("query").error?.message).toBe(
      CUSTOM_ATTACK_PATH_QUERY_READ_ONLY_ERROR_MESSAGE,
    );
    expect(result.current.isExecutionBlocked).toBe(true);
  });
});
