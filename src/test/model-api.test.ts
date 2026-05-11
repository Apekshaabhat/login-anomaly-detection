import { describe, expect, it, vi } from "vitest";
import { fetchModelStatus } from "@/lib/api";

describe("model api", () => {
  it("reads model status from the backend model endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ model_name: "Isolation Forest", status: "healthy" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const status = await fetchModelStatus();

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/model/status",
      expect.objectContaining({
        headers: expect.objectContaining({ "Content-Type": "application/json" }),
      }),
    );
    expect(status.model_name).toBe("Isolation Forest");
  });
});

