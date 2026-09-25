import './theme';
import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";
import { DialogHost } from "./components/DialogHost";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <DialogHost>
      <App />
    </DialogHost>
  </React.StrictMode>
);
