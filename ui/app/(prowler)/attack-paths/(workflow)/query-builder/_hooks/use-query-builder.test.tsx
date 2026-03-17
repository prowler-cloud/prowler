import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { AttackPathQuery } from "@/types/attack-paths";

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
});
