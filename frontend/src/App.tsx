import { Layout } from "./components/Layout";
import { usePage } from "./lib/router";
import Analytics from "./pages/Analytics";
import Docs from "./pages/Docs";
import Home from "./pages/Home";
import Playground from "./pages/Playground";

export default function App() {
  const page = usePage();
  return (
    <Layout page={page}>
      {page === "home" && <Home />}
      {page === "playground" && <Playground />}
      {page === "analytics" && <Analytics />}
      {page === "docs" && <Docs />}
    </Layout>
  );
}
