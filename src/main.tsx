import React from "react";
import ReactDOM from "react-dom/client";

import App from "./App";
import { useStore } from "./store";
import "./styles.css";

// Bootstrap outside React: StrictMode would otherwise run the effect twice and
// register a duplicate set of Tauri event listeners.
void useStore.getState().init();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
