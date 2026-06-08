(function () {
  const body = document.getElementById("terminal-body");
  const log = document.getElementById("output-log");
  const input = document.getElementById("cmd-input");
  const activeLine = document.getElementById("active-line");

  let commandHistory = [];
  let historyIndex = -1;

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  function currentPromptHtml() {
    const promptSpan = activeLine.querySelector(".prompt");
    return promptSpan.innerHTML;
  }

  function setPrompt(username, hostname, path) {
    const promptSpan = activeLine.querySelector(".prompt");
    promptSpan.innerHTML =
      `<span class="user">${escapeHtml(username)}@${escapeHtml(hostname)}</span>` +
      `:<span class="path">${escapeHtml(path)}</span>$`;
  }

  function appendEntry(promptHtml, commandText, output, isError) {
    const entry = document.createElement("div");
    entry.className = "entry";

    const echoed = document.createElement("div");
    echoed.className = "echoed-prompt";
    echoed.innerHTML = `${promptHtml} <span class="cmd-text">${escapeHtml(commandText)}</span>`;
    entry.appendChild(echoed);

    if (output) {
      const pre = document.createElement("pre");
      if (isError) pre.className = "error-output";
      pre.textContent = output;
      entry.appendChild(pre);
    }

    log.appendChild(entry);
  }

  function scrollToBottom() {
    body.scrollTop = body.scrollHeight;
  }

  async function runCommand(commandText) {
    const promptHtml = currentPromptHtml();

    if (commandText.trim().toLowerCase() === "clear") {
      log.innerHTML = "";
      try {
        await fetch("/api/run", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ command: commandText }),
        });
      } catch (e) {}
      return;
    }

    let data;
    try {
      const res = await fetch("/api/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: commandText }),
      });
      data = await res.json();
    } catch (e) {
      appendEntry(promptHtml, commandText, "Connection error: could not reach server.", true);
      scrollToBottom();
      return;
    }

    appendEntry(promptHtml, commandText, data.output, data.error);
    setPrompt(data.username, data.hostname, data.prompt_path);
    scrollToBottom();
  }

  input.addEventListener("keydown", function (e) {
    if (e.key === "Enter") {
      const value = input.value;
      input.value = "";
      if (value.trim().length > 0) {
        commandHistory.push(value);
      }
      historyIndex = commandHistory.length;
      runCommand(value);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (historyIndex > 0) {
        historyIndex -= 1;
        input.value = commandHistory[historyIndex] || "";
      }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (historyIndex < commandHistory.length - 1) {
        historyIndex += 1;
        input.value = commandHistory[historyIndex] || "";
      } else {
        historyIndex = commandHistory.length;
        input.value = "";
      }
    }
  });

  document.addEventListener("click", function () {
    input.focus();
  });

  input.focus();
})();
