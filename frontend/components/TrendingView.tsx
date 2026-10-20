"use client";

import { useEffect, useRef, useState } from "react";
import {
  ApiError,
  getTrending,
  searchCampaigns,
  type CampaignOut,
} from "@/lib/api";
import { defangUrl } from "@/lib/defang";

function formatDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) {
    return iso;
  }
  return d.toLocaleDateString();
}

// Small card for one campaign. Sample targets are plain defanged text,
// never links, and user text is rendered as-is (React escapes HTML).
function CampaignCard({ item }: { item: CampaignOut }) {
  return (
    <li className="campaign-row">
      <h3 className="campaign-title">{item.title}</h3>
      <p className="campaign-meta">
        <span className="campaign-type">Type: {item.scam_type}</span>{" "}
        <span className="campaign-count">
          {item.report_count}{" "}
          {item.report_count === 1 ? "report" : "reports"}
        </span>{" "}
        <span className="campaign-seen">
          Last seen {formatDate(item.last_seen)}
        </span>
      </p>
      {item.sample_targets.length > 0 ? (
        <ul className="campaign-samples" aria-label="Sample targets">
          {item.sample_targets.map((t) => (
            <li key={t} className="defanged">
              {defangUrl(t)}
            </li>
          ))}
        </ul>
      ) : (
        <p className="char-count">No sample link shared yet.</p>
      )}
    </li>
  );
}

export function CampaignList({ items }: { items: CampaignOut[] }) {
  if (items.length === 0) {
    return <p>No scams to show right now. Please check again later.</p>;
  }
  return (
    <ul className="campaign-list">
      {items.map((c) => (
        <CampaignCard key={`${c.title}-${c.last_seen}`} item={c} />
      ))}
    </ul>
  );
}

// Trending + search. Search waits 400 ms after typing stops and only
// calls the API when the query has 3 or more characters.
export default function TrendingView() {
  const [trending, setTrending] = useState<CampaignOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<CampaignOut[] | null>(null);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const data = await getTrending();
        if (!cancelled) {
          setTrending(data);
        }
      } catch (e) {
        if (!cancelled) {
          setLoadError(
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
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  // Search box handler: short queries (< 3 chars) clear results right away
  // and never hit the network. Longer queries mark searching=true; the
  // effect below only schedules the debounced network call.
  function handleQueryChange(value: string) {
    setQuery(value);
    const q = value.trim();
    if (q.length < 3) {
      if (timer.current !== null) {
        clearTimeout(timer.current);
        timer.current = null;
      }
      setResults(null);
      setSearching(false);
      setSearchError(null);
    } else {
      setSearching(true);
    }
  }

  // Debounced search; only runs for queries with 3+ characters.
  // State updates happen in the timeout/async callbacks, not in the body.
  useEffect(() => {
    const q = query.trim();
    if (q.length < 3) {
      return;
    }
    if (timer.current !== null) {
      clearTimeout(timer.current);
    }
    timer.current = setTimeout(() => {
      void (async () => {
        try {
          const data = await searchCampaigns(q);
          setResults(data);
          setSearchError(null);
        } catch (e) {
          setSearchError(
            e instanceof ApiError
              ? e.message
              : "Something went wrong. Please try again."
          );
          setResults([]);
        } finally {
          setSearching(false);
        }
      })();
    }, 400);
    return () => {
      if (timer.current !== null) {
        clearTimeout(timer.current);
      }
    };
  }, [query]);

  const showingSearch = query.trim().length >= 3;

  return (
    <div>
      <h1>Trending scams</h1>
      <p className="lede">
        Reports come from users and are reviewed, but may not be perfect.
      </p>

      {loading ? (
        <p role="status">Loading trending scams, please wait.</p>
      ) : loadError !== null ? (
        <p className="form-error" role="alert" aria-live="assertive">
          {loadError}
        </p>
      ) : (
        <section aria-label="Trending scams">
          <h2>Most reported this week</h2>
          <CampaignList items={trending} />
        </section>
      )}

      <section aria-label="Search scams">
        <h2>Search scams</h2>
        <label className="field-label" htmlFor="trending-search">
          Search by name or link
        </label>
        <input
          id="trending-search"
          className="text-input auth-input"
          type="search"
          placeholder="Type at least 3 letters, e.g. kyc"
          value={query}
          onChange={(e) => handleQueryChange(e.target.value)}
          aria-describedby="search-hint"
          autoComplete="off"
        />
        <p id="search-hint" className="char-count" aria-live="polite">
          {query.trim().length < 3
            ? "Type at least 3 characters to search."
            : searching
              ? "Searching, please wait."
              : results !== null
                ? `${results.length} ${results.length === 1 ? "result" : "results"} found.`
                : ""}
        </p>
        {searchError !== null && (
          <p className="form-error" role="alert" aria-live="assertive">
            {searchError}
          </p>
        )}
        {showingSearch &&
          !searching &&
          searchError === null &&
          results !== null && <CampaignList items={results} />}
      </section>
    </div>
  );
}
