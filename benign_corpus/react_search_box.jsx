import { useState } from "react";

export default function SearchBox({ onSubmit }) {
  const [query, setQuery] = useState("");

  function handleSubmit(event) {
    event.preventDefault();
    onSubmit(query.trim());
  }

  return (
    <form onSubmit={handleSubmit}>
      <label htmlFor="q">Search</label>
      <input
        id="q"
        type="search"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        maxLength={120}
      />
      {/* React auto-escapes {query} — no XSS risk here. */}
      <p>Buscando: {query}</p>
      <button type="submit">Go</button>
    </form>
  );
}
