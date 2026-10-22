// A tiny hash router: four pages do not need a routing library.
import { useEffect, useState } from "react";

export type Page = "home" | "playground" | "analytics" | "docs";
export const PAGES: Page[] = ["home", "playground", "analytics", "docs"];

export function pageFromHash(hash: string): Page {
  const name = hash.replace(/^#\/?/, "").split(/[/?]/)[0];
  return (PAGES as string[]).includes(name) ? (name as Page) : "home";
}

export function hrefFor(page: Page): string {
  return page === "home" ? "#/" : `#/${page}`;
}

export function usePage(): Page {
  const [page, setPage] = useState<Page>(() => pageFromHash(window.location.hash));
  useEffect(() => {
    const update = () => {
      setPage(pageFromHash(window.location.hash));
      window.scrollTo({ top: 0 });
    };
    window.addEventListener("hashchange", update);
    return () => window.removeEventListener("hashchange", update);
  }, []);
  return page;
}
