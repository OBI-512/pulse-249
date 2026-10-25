import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { DialogProvider } from "./components/common/DialogSystem";
import { FeedbackProvider } from "./components/common/FeedbackSystem";

const savedTheme = localStorage.getItem("fttw_theme");
const initialTheme = savedTheme === "light" || savedTheme === "night" || savedTheme === "operations" ? savedTheme : "operations";
document.documentElement.dataset.theme = initialTheme;
document.documentElement.style.colorScheme = initialTheme === "night" ? "dark" : "light";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <FeedbackProvider>
      <DialogProvider>
        <App />
      </DialogProvider>
    </FeedbackProvider>
  </StrictMode>,
);
