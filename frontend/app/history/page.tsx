"use client";

import { useEffect, useState } from "react";
import HistoryList from "@/components/HistoryList";
import RequireAuth from "@/components/RequireAuth";
import { ApiError, getHistory, type ScanHistoryItem } from "@/lib/api";

const PAGE_SIZE = 20;

function HistoryInner() {
  const [items, setItems] = useState<ScanHistoryItem[]>([]);
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function initial() {
      try {
        const batch = await getHistory(PAGE_SIZE, 0);
        if (cancelled) {
          return;
        }
        setItems(batch);
        setOffset(batch.length);
        setHasMore(batch.length === PAGE_SIZE);
      } catch (e) {
        if (!cancelled) {
          setError(
            e instanceof ApiError
              ? e.message
              : "Something went wrong. Please try again."
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }
    void initial();
    return () => {
      cancelled = true;
    };
  }, []);

  async function loadMore() {
    setLoadingMore(true);
    try {
      const batch = await getHistory(PAGE_SIZE, offset);
      setItems((prev) => [...prev, ...batch]);
      setOffset(offset + batch.length);
      setHasMore(batch.length === PAGE_SIZE);
    } catch (e) {
      setError(
        e instanceof ApiError ? e.message : "Something went wrong. Please try again."
      );
    } finally {
      setLoadingMore(false);
    }
  }

  if (loading) {
    return (
      <div>
        <h1>Your scan history</h1>
        <p role="status">Loading your scans, please wait.</p>
      </div>
    );
  }

  return (
    <div>
      <h1>Your scan history</h1>
      {error !== null && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      <HistoryList items={items} />
      {hasMore && items.length > 0 && (
        <p>
          <button
            type="button"
            className="btn btn-primary"
            disabled={loadingMore}
            aria-busy={loadingMore}
            onClick={() => void loadMore()}
          >
            {loadingMore ? "Loading…" : "Load more"}
          </button>
        </p>
      )}
    </div>
  );
}

export default function HistoryPage() {
  return (
    <RequireAuth>
      <HistoryInner />
    </RequireAuth>
  );
}
