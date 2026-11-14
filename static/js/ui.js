(function (window) {
    'use strict';

    // Fluent UI System Icons by Microsoft Corporation (MIT License)
    var FLUENT_ICONS = {
  "shield-checkmark": "<path d=\"M9.72 2.08a.5.5 0 0 1 .56 0q2.9 1.94 6.3 2.43A.5.5 0 0 1 17 5v4.6q-.48-.25-1-.4V5.44a16 16 0 0 1-5.6-2.08L10 3.1l-.4.25A16 16 0 0 1 4 5.43V9.5c0 3.24 1.8 5.64 5.48 7.25q.3.65.74 1.2l-.04.02a.5.5 0 0 1-.36 0C5.31 16.23 3 13.39 3 9.5V5a.5.5 0 0 1 .43-.5 15 15 0 0 0 6.3-2.42M19 14.5a4.5 4.5 0 1 1-9 0 4.5 4.5 0 0 1 9 0m-2.15-1.85a.5.5 0 0 0-.7 0l-2.65 2.64-.65-.64a.5.5 0 0 0-.7.7l1 1c.2.2.5.2.7 0l3-3a.5.5 0 0 0 0-.7\"/>",
  "shield-checkmark-filled": "<path d=\"M9.72 2.08a.5.5 0 0 1 .56 0q2.9 1.94 6.3 2.43A.5.5 0 0 1 17 5v4.6Q15.86 9 14.5 9a5.5 5.5 0 0 0-4.28 8.95l-.04.02a.5.5 0 0 1-.36 0C5.31 16.23 3 13.39 3 9.5V5a.5.5 0 0 1 .43-.5 15 15 0 0 0 6.3-2.42M19 14.5a4.5 4.5 0 1 0-9 0 4.5 4.5 0 0 0 9 0m-2.15-1.85c.2.2.2.5 0 .7l-3 3a.5.5 0 0 1-.7 0l-1-1a.5.5 0 0 1 .7-.7l.65.64 2.65-2.64c.2-.2.5-.2.7 0\"/>",
  "shield-lock": "<path d=\"M9.72 2.08a.5.5 0 0 1 .56 0q2.9 1.94 6.3 2.43A.5.5 0 0 1 17 5v4.34q-.4-.57-1-.94V5.43a16 16 0 0 1-5.6-2.08L10 3.1l-.4.25A16 16 0 0 1 4 5.43V9.5c0 3.4 1.97 5.86 6 7.46V17a2 2 0 0 0 .24.94l-.06.03a.5.5 0 0 1-.36 0C5.31 16.23 3 13.39 3 9.5V5a.5.5 0 0 1 .43-.5 15 15 0 0 0 6.3-2.42M12.5 12v-1a2 2 0 1 1 4 0v1h.5a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1h-5a1 1 0 0 1-1-1v-4a1 1 0 0 1 1-1zm1-1v1h2v-1a1 1 0 1 0-2 0m1.75 4a.75.75 0 1 0-1.5 0 .75.75 0 0 0 1.5 0\"/>",
  "shield-keyhole": "<path d=\"M11.5 9c0 .65-.42 1.2-1 1.41v2.09a.5.5 0 0 1-1 0v-2.09a1.5 1.5 0 1 1 2-1.41m-1.22-6.92a.5.5 0 0 0-.56 0 15 15 0 0 1-6.3 2.43A.5.5 0 0 0 3 5v4.5q.02 5.86 6.82 8.47a.5.5 0 0 0 .36 0C14.69 16.23 17 13.39 17 9.5V5a.5.5 0 0 0-.43-.5 15 15 0 0 1-6.3-2.42M4 5.43a16 16 0 0 0 5.6-2.08l.4-.25.4.25A16 16 0 0 0 16 5.43V9.5c0 3.4-1.97 5.86-6 7.46-4.03-1.6-6-4.07-6-7.46z\"/>",
  "shield-error": "<path d=\"M10 6c.28 0 .5.22.5.5v5a.5.5 0 0 1-1 0v-5c0-.28.22-.5.5-.5m0 8.5a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5M9.72 2.08a.5.5 0 0 1 .56 0q2.9 1.94 6.3 2.43A.5.5 0 0 1 17 5v4.5c0 3.9-2.3 6.73-6.82 8.47a.5.5 0 0 1-.36 0C5.31 16.23 3 13.39 3 9.5V5a.5.5 0 0 1 .43-.5 15 15 0 0 0 6.3-2.42M9.6 3.35A16 16 0 0 1 4 5.43V9.5c0 3.4 1.97 5.86 6 7.46 4.03-1.6 6-4.07 6-7.46V5.43a16 16 0 0 1-5.6-2.08L10 3.1z\"/>",
  "shield-person": "<path d=\"M10 9.5a2 2 0 1 0 0-4 2 2 0 0 0 0 4m0 5c2.5 0 3.5-1.26 3.5-2.5 0-.83-.67-1.5-1.5-1.5H8c-.83 0-1.5.67-1.5 1.5 0 1.25 1 2.5 3.5 2.5m.28-12.42a.5.5 0 0 0-.56 0 15 15 0 0 1-6.3 2.43A.5.5 0 0 0 3 5v4.5q.02 5.86 6.82 8.47a.5.5 0 0 0 .36 0C14.69 16.23 17 13.39 17 9.5V5a.5.5 0 0 0-.43-.5 15 15 0 0 1-6.3-2.42M4 5.43a16 16 0 0 0 5.6-2.08l.4-.25.4.25A16 16 0 0 0 16 5.43V9.5c0 3.4-1.97 5.86-6 7.46-4.03-1.6-6-4.07-6-7.46z\"/>",
  "lock-closed": "<path d=\"M10 1a4 4 0 0 1 4 4v2.05a2.5 2.5 0 0 1 2 2.45v6a2.5 2.5 0 0 1-2.5 2.5h-7A2.5 2.5 0 0 1 4 15.5v-6c0-1.2.86-2.22 2-2.45V5a4 4 0 0 1 4-4M6.5 8C5.67 8 5 8.67 5 9.5v6c0 .83.67 1.5 1.5 1.5h7c.83 0 1.5-.67 1.5-1.5v-6c0-.83-.67-1.5-1.5-1.5zm3.5 3.5a1 1 0 1 1 0 2 1 1 0 0 1 0-2M10 2a3 3 0 0 0-3 3v2h6V5a3 3 0 0 0-3-3\"/>",
  "lock-open": "<path d=\"M15 1a4 4 0 0 1 4 4v.5a.5.5 0 0 1-1 0V5a3 3 0 1 0-6 0v2h1.5A2.5 2.5 0 0 1 16 9.5v6a2.5 2.5 0 0 1-2.5 2.5h-7A2.5 2.5 0 0 1 4 15.5v-6A2.5 2.5 0 0 1 6.5 7H11V5a4 4 0 0 1 4-4M6.5 8C5.67 8 5 8.67 5 9.5v6c0 .83.67 1.5 1.5 1.5h7c.83 0 1.5-.67 1.5-1.5v-6c0-.83-.67-1.5-1.5-1.5zm3.5 3.5a1 1 0 1 1 0 2 1 1 0 0 1 0-2\"/>",
  "key": "<path d=\"M15 6a1 1 0 1 1-2 0 1 1 0 0 1 2 0m-2.5-4a5.45 5.45 0 0 0-5.38 6.67q.08.42-.14.64l-4.54 4.54A1.5 1.5 0 0 0 2 14.91v1.59c0 .83.67 1.5 1.5 1.5h2c.83 0 1.5-.67 1.5-1.5V16h1a1 1 0 0 0 1-1v-1h1a1 1 0 0 0 1-1v-.18q.75.19 1.5.18c3.08 0 5.5-2.42 5.5-5.5S15.58 2 12.5 2M8 7.5C8 4.98 9.98 3 12.5 3S17 4.98 17 7.5 15.02 12 12.5 12q-1 .01-1.78-.35a.5.5 0 0 0-.72.45v.9H9a1 1 0 0 0-1 1v1H7a1 1 0 0 0-1 1v.5a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1-.5-.5v-1.59a.5.5 0 0 1 .15-.35l4.54-4.54c.43-.43.52-1.04.4-1.56Q8 8 8 7.5\"/>",
  "key-reset": "<path d=\"M14 7a1 1 0 1 0 0-2 1 1 0 0 0 0 2m-7 .5C7 4.42 9.42 2 12.5 2S18 4.42 18 7.5q-.02 1.51-.7 2.74a5 5 0 0 0-.83-.59q.52-.96.53-2.15C17 4.98 15.02 3 12.5 3a4.45 4.45 0 0 0-4.4 5.46c.1.52.02 1.13-.41 1.56l-4.54 4.54a.5.5 0 0 0-.15.35v1.59c0 .28.22.5.5.5h2a.5.5 0 0 0 .5-.5V16a1 1 0 0 1 1-1h1v-1a1 1 0 0 1 1-1h.38A1.5 1.5 0 0 0 9 14v1a1 1 0 0 1-1 1H7v.5c0 .83-.67 1.5-1.5 1.5h-2A1.5 1.5 0 0 1 2 16.5v-1.59q.01-.62.44-1.06l4.54-4.54q.21-.21.14-.64A6 6 0 0 1 7 7.5m4.85 1.35a.5.5 0 0 0-.7-.7l-2 2a.5.5 0 0 0 0 .7l2 2a.5.5 0 0 0 .7-.7L10.71 11H14a3 3 0 1 1-3 3 .5.5 0 1 0-1 0 4 4 0 1 0 4-4h-3.3z\"/>",
  "eye": "<path d=\"M3.26 11.6A7 7 0 0 1 10 6c3.2 0 6.06 2.33 6.74 5.6a.5.5 0 0 0 .98-.2A8 8 0 0 0 10 5a8 8 0 0 0-7.72 6.4.5.5 0 0 0 .98.2M10 8a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7m-2.5 3.5a2.5 2.5 0 1 1 5 0 2.5 2.5 0 0 1-5 0\"/>",
  "eye-off": "<path d=\"M2.85 2.15a.5.5 0 1 0-.7.7l3.5 3.5a8 8 0 0 0-3.37 5.05.5.5 0 1 0 .98.2 7 7 0 0 1 3.1-4.53l1.6 1.59a3.5 3.5 0 1 0 4.88 4.89l4.3 4.3a.5.5 0 0 0 .71-.7zm9.27 10.68a2.5 2.5 0 1 1-3.45-3.45zm-2-4.83 3.38 3.38A3.5 3.5 0 0 0 10.12 8M10 6q-.86 0-1.67.21l-.8-.8A8 8 0 0 1 10 5c3.7 0 6.94 2.67 7.72 6.4a.5.5 0 0 1-.98.2A7 7 0 0 0 10 6\"/>",
  "mail": "<path d=\"M15.5 4A2.5 2.5 0 0 1 18 6.5v8a2.5 2.5 0 0 1-2.5 2.5h-11A2.5 2.5 0 0 1 2 14.5v-8A2.5 2.5 0 0 1 4.5 4zM17 7.96l-6.75 3.97a.5.5 0 0 1-.42.04l-.08-.04L3 7.96v6.54c0 .83.67 1.5 1.5 1.5h11c.83 0 1.5-.67 1.5-1.5zM15.5 5h-11C3.67 5 3 5.67 3 6.5v.3l7 4.12 7-4.12v-.3c0-.83-.67-1.5-1.5-1.5\"/>",
  "phone": "<path d=\"M9 14a.5.5 0 0 0 0 1h2a.5.5 0 0 0 0-1zM7 2a2 2 0 0 0-2 2v12c0 1.1.9 2 2 2h6a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2zM6 4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1z\"/>",
  "call": "<path d=\"m6.99 2.07-.72.21a3.5 3.5 0 0 0-2.45 2.86q-.44 3.1 1.96 7.25t5.3 5.33a3.5 3.5 0 0 0 3.7-.7l.55-.52a2 2 0 0 0 .25-2.62L14.22 12a1.5 1.5 0 0 0-1.65-.56l-2.05.63-.06.01c-.22.04-.74-.45-1.4-1.58-.67-1.18-.82-1.87-.63-2.04l1.05-.98a2.5 2.5 0 0 0 .57-2.85l-.66-1.47a2 2 0 0 0-2.4-1.1m1.49 1.5.66 1.47a1.5 1.5 0 0 1-.35 1.71l-1.04.98c-.67.63-.45 1.71.45 3.27.85 1.47 1.62 2.19 2.45 2.06l.12-.02 2.09-.64a.5.5 0 0 1 .55.19l1.36 1.88a1 1 0 0 1-.13 1.3l-.54.52a2.5 2.5 0 0 1-2.65.5q-2.55-1.01-4.8-4.9T4.81 5.28a2.5 2.5 0 0 1 1.75-2.04l.72-.22a1 1 0 0 1 1.2.55\"/>",
  "person": "<path d=\"M10 2a4 4 0 1 0 0 8 4 4 0 0 0 0-8M7 6a3 3 0 1 1 6 0 3 3 0 0 1-6 0m-2 5a2 2 0 0 0-2 2c0 1.7.83 2.97 2.13 3.8A9 9 0 0 0 10 18c1.85 0 3.58-.39 4.87-1.2A4.4 4.4 0 0 0 17 13a2 2 0 0 0-2-2zm-1 2a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1c0 1.3-.62 2.28-1.67 2.95A8 8 0 0 1 10 17a8 8 0 0 1-4.33-1.05A3.4 3.4 0 0 1 4 13\"/>",
  "person-circle": "<path d=\"M8 7a2 2 0 1 1 4 0 2 2 0 0 1-4 0m-.5 3h5c.83 0 1.5.67 1.5 1.5 0 1.12-.46 2.01-1.21 2.61-.74.6-1.74.89-2.79.89a4.4 4.4 0 0 1-2.79-.89A3.3 3.3 0 0 1 6 11.5c0-.83.67-1.5 1.5-1.5M10 2a8 8 0 1 0 0 16 8 8 0 0 0 0-16m-7 8a7 7 0 1 1 14 0 7 7 0 0 1-14 0\"/>",
  "person-swap": "<path d=\"M9 2a4 4 0 1 0 0 8 4 4 0 0 0 0-8M6 6a3 3 0 1 1 6 0 3 3 0 0 1-6 0m-2 5a2 2 0 0 0-2 2c0 1.7.83 2.97 2.13 3.8A9 9 0 0 0 9 18q.43 0 .85-.03L8.88 17a8 8 0 0 1-4.2-1.05A3.4 3.4 0 0 1 3 13a1 1 0 0 1 1-1h10a1 1 0 0 1 .67.25q.5-.33 1.07-.23A2 2 0 0 0 14 11zm7.85 6.85a.5.5 0 0 1-.7 0l-2-2a.5.5 0 0 1 0-.7l2-2a.5.5 0 0 1 .7.7L10.71 15h5.58l-1.14-1.15a.5.5 0 0 1 .7-.7l2 2c.2.2.2.5 0 .7l-2 2a.5.5 0 0 1-.7-.7L16.29 16h-5.58l1.14 1.15c.2.2.2.5 0 .7\"/>",
  "person-delete": "<path d=\"M5 6a4 4 0 1 1 8 0 4 4 0 0 1-8 0m4-3a3 3 0 1 0 0 6 3 3 0 0 0 0-6M2 13a2 2 0 0 1 2-2h6.26q-.39.46-.66 1H4a1 1 0 0 0-1 1c0 1.3.62 2.28 1.67 2.95A8 8 0 0 0 9 17l.6-.01q.25.51.61.95Q9.61 18 9 18a9 9 0 0 1-4.87-1.2A4.4 4.4 0 0 1 2 13m17 1.5a4.5 4.5 0 1 1-9 0 4.5 4.5 0 0 1 9 0m-2.65-1.15a.5.5 0 0 0-.7-.7l-1.15 1.14-1.15-1.14a.5.5 0 0 0-.7.7l1.14 1.15-1.14 1.15a.5.5 0 0 0 .7.7l1.15-1.14 1.15 1.14a.5.5 0 0 0 .7-.7l-1.14-1.15z\"/>",
  "person-accounts": "<path d=\"M9 2a4 4 0 1 0 0 8 4 4 0 0 0 0-8M6 6a3 3 0 1 1 6 0 3 3 0 0 1-6 0m-2 5a2 2 0 0 0-2 2c0 1.7.83 2.97 2.13 3.8A9 9 0 0 0 9 18h.05a3 3 0 0 1-.05-.5V17a8 8 0 0 1-4.33-1.05A3.4 3.4 0 0 1 3 13a1 1 0 0 1 1-1h5.5c.37-.5.91-.84 1.54-.96l.01-.04zm8 .5v.5h-.5c-.83 0-1.5.67-1.5 1.5v4c0 .83.67 1.5 1.5 1.5h6c.83 0 1.5-.67 1.5-1.5v-4c0-.83-.67-1.5-1.5-1.5H17v-.5c0-.83-.67-1.5-1.5-1.5h-2c-.83 0-1.5.67-1.5 1.5m1.5-.5h2c.28 0 .5.22.5.5v.5h-3v-.5c0-.28.22-.5.5-.5\"/>",
  "people": "<path d=\"M4.5 6.75a2.25 2.25 0 1 1 4.5 0 2.25 2.25 0 0 1-4.5 0M6.75 3.5a3.25 3.25 0 1 0 0 6.5 3.25 3.25 0 0 0 0-6.5m5.69 11.65q.79.33 2.06.35c1.88 0 2.92-.67 3.47-1.43a3 3 0 0 0 .53-1.5v-.07c0-.83-.67-1.5-1.5-1.5h-4.63q.36.44.53 1H17c.28 0 .5.22.5.5v.1l-.04.22q-.05.29-.3.66c-.33.46-1.04 1.02-2.66 1.02q-1.08-.01-1.69-.28-.12.43-.37.93M1.5 13c0-1.1.9-2 2-2H10a2 2 0 0 1 2 2v.08l-.01.18q-.01.17-.08.45c-.08.37-.25.86-.6 1.36-.7 1.01-2.05 1.93-4.56 1.93s-3.87-.92-4.57-1.93a4 4 0 0 1-.68-1.99V13m1 .06v.1l.06.33c.07.27.2.64.45 1C3.49 15.2 4.5 16 6.75 16s3.26-.8 3.74-1.5a3 3 0 0 0 .5-1.42l.01-.02V13a1 1 0 0 0-1-1H3.5a1 1 0 0 0-1 1zM13 7.5a1.5 1.5 0 1 1 3 0 1.5 1.5 0 0 1-3 0M14.5 5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5\"/>",
  "apps": "<path d=\"M4.5 17A1.5 1.5 0 0 1 3 15.65V4.5c0-.78.6-1.42 1.36-1.5H9c.78 0 1.42.6 1.5 1.36v.4l2.19-2.27a1.5 1.5 0 0 1 2-.14l.12.1 2.76 2.72c.55.55.6 1.42.11 2.02l-.1.11-2.31 2.2h.23c.78 0 1.42.6 1.5 1.36v4.64c0 .78-.6 1.42-1.36 1.5H4.5m5-6.5H4v5c0 .22.14.4.33.47l.08.02.09.01h5zm6 0h-5V16h5a.5.5 0 0 0 .5-.4V11a.5.5 0 0 0-.41-.5zm-5-2.79V9.5h1.79zM9 4.01H4.5a.5.5 0 0 0-.5.4v5.1h5.5v-5a.5.5 0 0 0-.33-.48l-.08-.02zm5.12-.84a.5.5 0 0 0-.64-.05l-.07.06-2.62 2.71a.5.5 0 0 0-.05.63l.06.07 2.61 2.62c.17.17.43.2.62.07l.08-.06 2.76-2.63a.5.5 0 0 0 .05-.64l-.05-.06z\"/>",
  "laptop": "<path d=\"M3 7c0-1.1.9-2 2-2h10a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2zm2-1a1 1 0 0 0-1 1v5a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V7a1 1 0 0 0-1-1zm-3 9.5c0-.28.22-.5.5-.5h15a.5.5 0 0 1 0 1h-15a.5.5 0 0 1-.5-.5\"/>",
  "desktop": "<path d=\"M4 2a2 2 0 0 0-2 2v9c0 1.1.9 2 2 2h3v2H5.5a.5.5 0 0 0 0 1h9a.5.5 0 0 0 0-1H13v-2h3a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2zm8 13v2H8v-2zM3 4a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z\"/>",
  "tablet": "<path d=\"M8.5 12a.5.5 0 0 0 0 1h3a.5.5 0 0 0 0-1zM4 4a2 2 0 0 0-2 2v8c0 1.1.9 2 2 2h12a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2zM3 6a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z\"/>",
  "phone-laptop": "<path d=\"M3 4.5C3 3.67 3.67 3 4.5 3h11c.83 0 1.5.67 1.5 1.5v7c0 .83-.67 1.5-1.5 1.5H10v-1h5.5a.5.5 0 0 0 .5-.5v-7a.5.5 0 0 0-.5-.5h-11a.5.5 0 0 0-.5.5V6H3zM10 15h7.5a.5.5 0 0 0 0-1H10zm-5 0a.5.5 0 0 0 0 1h1a.5.5 0 0 0 0-1zM2 8.5C2 7.67 2.67 7 3.5 7h4C8.33 7 9 7.67 9 8.5v8c0 .83-.67 1.5-1.5 1.5h-4A1.5 1.5 0 0 1 2 16.5zM3.5 8a.5.5 0 0 0-.5.5v8c0 .28.22.5.5.5h4a.5.5 0 0 0 .5-.5v-8a.5.5 0 0 0-.5-.5z\"/>",
  "qr-code": "<path d=\"M11 15h2v2h-2zm4 0h2v2h-2zm-4-4h2v2h-2zm2 2h2v2h-2zm2-2h2v2h-2zM3 5c0-1.1.9-2 2-2h2a2 2 0 0 1 2 2v2a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2zm2-1a1 1 0 0 0-1 1v2a1 1 0 0 0 1 1h2a1 1 0 0 0 1-1V5a1 1 0 0 0-1-1zm0 1h2v2H5zm-2 8c0-1.1.9-2 2-2h2a2 2 0 0 1 2 2v2a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2zm2-1a1 1 0 0 0-1 1v2a1 1 0 0 0 1 1h2a1 1 0 0 0 1-1v-2a1 1 0 0 0-1-1zm0 1h2v2H5zm6-8c0-1.1.9-2 2-2h2a2 2 0 0 1 2 2v2a2 2 0 0 1-2 2h-2a2 2 0 0 1-2-2zm2-1a1 1 0 0 0-1 1v2a1 1 0 0 0 1 1h2a1 1 0 0 0 1-1V5a1 1 0 0 0-1-1zm0 1h2v2h-2z\"/>",
  "copy": "<path d=\"M7 7H5a2 2 0 0 0-2 2v6c0 1.1.9 2 2 2h4a2 2 0 0 0 2-2h1a3 3 0 0 1-3 3H5a3 3 0 0 1-3-3V9a3 3 0 0 1 3-3h2zm8-5a3 3 0 0 1 3 3v6a3 3 0 0 1-3 3h-4a3 3 0 0 1-3-3V5a3 3 0 0 1 3-3zm-4 1a2 2 0 0 0-2 2v6c0 1.1.9 2 2 2h4a2 2 0 0 0 2-2V5a2 2 0 0 0-2-2z\"/>",
  "checkmark": "<path d=\"M3.37 10.17a.5.5 0 0 0-.74.66l4 4.5c.19.22.52.23.72.02l10.5-10.5a.5.5 0 0 0-.7-.7L7.02 14.27z\"/>",
  "checkmark-circle": "<path d=\"M10 2a8 8 0 1 1 0 16 8 8 0 0 1 0-16m0 1a7 7 0 1 0 0 14 7 7 0 0 0 0-14m3.36 4.65c.17.17.2.44.06.63l-.06.07-4 4a.5.5 0 0 1-.64.07l-.07-.06-2-2a.5.5 0 0 1 .63-.77l.07.06L9 11.3l3.65-3.65c.2-.2.51-.2.7 0\"/>",
  "checkmark-circle-filled": "<path d=\"M10 2a8 8 0 1 1 0 16 8 8 0 0 1 0-16m3.36 5.65a.5.5 0 0 0-.64-.06l-.07.06L9 11.3 7.35 9.65l-.07-.06a.5.5 0 0 0-.7.7l.07.07 2 2 .07.06c.17.11.4.11.56 0l.07-.06 4-4 .07-.08a.5.5 0 0 0-.06-.63\"/>",
  "checkmark-starburst": "<path d=\"M11.54 1.9c1.21-.48 2.58.09 3.1 1.28l.43.98q.24.53.77.77l.98.43a2.4 2.4 0 0 1 1.28 3.1l-.39 1a1.5 1.5 0 0 0 0 1.09l.4.99a2.4 2.4 0 0 1-1.3 3.1l-.97.43a1.5 1.5 0 0 0-.77.77l-.43.98a2.4 2.4 0 0 1-3.1 1.28l-.99-.39a1.5 1.5 0 0 0-1.1 0l-.99.4a2.4 2.4 0 0 1-3.1-1.3l-.42-.97a1.5 1.5 0 0 0-.78-.77l-.98-.43a2.4 2.4 0 0 1-1.28-3.1l.39-.99a1.5 1.5 0 0 0 0-1.1l-.4-.99a2.4 2.4 0 0 1 1.3-3.1l.97-.43q.53-.24.78-.77l.42-.98a2.4 2.4 0 0 1 3.1-1.28l1 .39q.54.21 1.1 0zm2.19 1.68c-.3-.7-1.11-1.03-1.82-.75l-1 .39a2.5 2.5 0 0 1-1.82 0l-1-.4a1.4 1.4 0 0 0-1.81.76l-.43.98a2.5 2.5 0 0 1-1.3 1.3l-.97.42c-.7.3-1.03 1.1-.75 1.82l.39.99a2.5 2.5 0 0 1 0 1.83l-.4.99c-.27.7.06 1.51.76 1.81l.98.43a2.5 2.5 0 0 1 1.3 1.3l.42.97c.3.7 1.1 1.03 1.82.75l.99-.39a2.5 2.5 0 0 1 1.83 0l.99.4c.7.27 1.51-.06 1.82-.76l.42-.98a2.5 2.5 0 0 1 1.3-1.3l.97-.42c.7-.3 1.03-1.1.75-1.81l-.39-1a2.5 2.5 0 0 1 0-1.82l.4-1a1.4 1.4 0 0 0-.76-1.81l-.98-.43a2.5 2.5 0 0 1-1.29-1.3zm-1.08 4.07a.5.5 0 0 1 .7.7l-4 4a.5.5 0 0 1-.7 0l-2-2a.5.5 0 1 1 .7-.7L9 11.29z\"/>",
  "dismiss": "<path d=\"m4.09 4.22.06-.07a.5.5 0 0 1 .63-.06l.07.06L10 9.29l5.15-5.14a.5.5 0 0 1 .63-.06l.07.06c.18.17.2.44.06.63l-.06.07L10.71 10l5.14 5.15c.18.17.2.44.06.63l-.06.07a.5.5 0 0 1-.63.06l-.07-.06L10 10.71l-5.15 5.14a.5.5 0 0 1-.63.06l-.07-.06a.5.5 0 0 1-.06-.63l.06-.07L9.29 10 4.15 4.85a.5.5 0 0 1-.06-.63l.06-.07z\"/>",
  "dismiss-circle": "<path d=\"M10 2a8 8 0 1 1 0 16 8 8 0 0 1 0-16m0 1a7 7 0 1 0 0 14 7 7 0 0 0 0-14M7.8 7.11l.08.06L10 9.3l2.12-2.12a.5.5 0 0 1 .64-.06l.07.06c.17.18.2.44.06.64l-.06.07L10.7 10l2.12 2.12c.17.17.2.44.06.64l-.06.07a.5.5 0 0 1-.64.06l-.07-.06L10 10.7l-2.12 2.12a.5.5 0 0 1-.64.06l-.07-.06a.5.5 0 0 1-.06-.64l.06-.07L9.3 10 7.17 7.88a.5.5 0 0 1-.06-.64l.06-.07a.5.5 0 0 1 .64-.06\"/>",
  "error-circle": "<path d=\"M10 2a8 8 0 1 1 0 16 8 8 0 0 1 0-16m0 1a7 7 0 1 0 0 14 7 7 0 0 0 0-14m0 9.5a.75.75 0 1 1 0 1.5.75.75 0 0 1 0-1.5M10 6a.5.5 0 0 1 .5.41V11a.5.5 0 0 1-1 .09V6.5c0-.28.22-.5.5-.5\"/>",
  "warning": "<path d=\"M7.37 3.56a3 3 0 0 1 5.26 0l5.5 10A3 3 0 0 1 15.5 18h-11a3 3 0 0 1-2.63-4.44zm4.38.48a2 2 0 0 0-3.5 0l-5.5 10A2 2 0 0 0 4.5 17h11a2 2 0 0 0 1.75-2.96zM10 12.75a.75.75 0 1 1 0 1.5.75.75 0 0 1 0-1.5m0-6.25c.28 0 .5.22.5.5v4a.5.5 0 0 1-1 0V7c0-.28.22-.5.5-.5\"/>",
  "info": "<path d=\"M10.5 8.91a.5.5 0 0 0-1 .09v4.6a.5.5 0 0 0 1-.1V8.91m.3-2.16a.75.75 0 1 0-1.5 0 .75.75 0 0 0 1.5 0M18 10a8 8 0 1 0-16 0 8 8 0 0 0 16 0M3 10a7 7 0 1 1 14 0 7 7 0 0 1-14 0\"/>",
  "arrow-left": "<path d=\"M9.16 16.87a.5.5 0 1 0 .67-.74L3.67 10.5H17.5a.5.5 0 0 0 0-1H3.67l6.16-5.63a.5.5 0 0 0-.67-.74L2.24 9.44a.75.75 0 0 0 0 1.11z\"/>",
  "arrow-right": "<path d=\"M10.84 3.13a.5.5 0 0 0-.68.74l6.17 5.63H2.5a.5.5 0 0 0 0 1h13.83l-6.17 5.63a.5.5 0 0 0 .68.74l6.91-6.32a.75.75 0 0 0 0-1.1z\"/>",
  "arrow-sync": "<path d=\"M11.41 3.64a.5.5 0 0 0 0-.71L9.3.8a.5.5 0 0 0-.7.7l1 1a7.5 7.5 0 0 0-4.08 13.5.5.5 0 0 0 .6-.8A6.5 6.5 0 0 1 10.14 3.5L8.59 5.04a.5.5 0 0 0 .7.7zM8.6 16.36a.5.5 0 0 0 0 .71l2.12 2.12a.5.5 0 0 0 .7-.7l-1-1a7.5 7.5 0 0 0 4.07-13.5.5.5 0 1 0-.59.8q.37.28.7.61a6.5 6.5 0 0 1-4.73 11.1l1.55-1.55a.5.5 0 1 0-.7-.7z\"/>",
  "chevron-down": "<path d=\"M15.85 7.65c.2.2.2.5 0 .7l-5.46 5.49a.55.55 0 0 1-.78 0L4.15 8.35a.5.5 0 1 1 .7-.7L10 12.8l5.15-5.16c.2-.2.5-.2.7 0\"/>",
  "chevron-right": "<path d=\"M7.65 4.15c.2-.2.5-.2.7 0l5.49 5.46c.21.22.21.57 0 .78l-5.49 5.47a.5.5 0 0 1-.7-.71L12.8 10 7.65 4.85a.5.5 0 0 1 0-.7\"/>",
  "chevron-up": "<path d=\"M4.15 12.35a.5.5 0 0 1 0-.7L9.6 6.16a.55.55 0 0 1 .78 0l5.47 5.49a.5.5 0 0 1-.71.7L10 7.2l-5.15 5.16a.5.5 0 0 1-.7 0\"/>",
  "settings": "<path d=\"M1.91 7.38A8.5 8.5 0 0 1 3.7 4.3a.5.5 0 0 1 .54-.13l1.92.68a1 1 0 0 0 1.32-.76l.36-2a.5.5 0 0 1 .4-.4 9 9 0 0 1 3.55 0q.32.08.38.4l.37 2a1 1 0 0 0 1.32.76l1.92-.68a.5.5 0 0 1 .54.13 8.5 8.5 0 0 1 1.78 3.08q.08.31-.15.54l-1.56 1.32a1 1 0 0 0 0 1.52l1.56 1.32a.5.5 0 0 1 .15.54 8.5 8.5 0 0 1-1.78 3.08.5.5 0 0 1-.54.13l-1.92-.68a1 1 0 0 0-1.32.76l-.37 2a.5.5 0 0 1-.38.4 8.5 8.5 0 0 1-3.56 0 .5.5 0 0 1-.39-.4l-.36-2a1 1 0 0 0-1.32-.76l-1.92.68a.5.5 0 0 1-.54-.13 8.5 8.5 0 0 1-1.78-3.08.5.5 0 0 1 .15-.54l1.56-1.32a1 1 0 0 0 0-1.52L2.06 7.92a.5.5 0 0 1-.15-.54m1.06 0 1.3 1.1a2 2 0 0 1 0 3.04l-1.3 1.1q.45 1.19 1.25 2.16l1.6-.58a2 2 0 0 1 2.63 1.53l.3 1.67a8 8 0 0 0 2.5 0l.3-1.67a2 2 0 0 1 2.64-1.53l1.6.58a8 8 0 0 0 1.24-2.16l-1.3-1.1a2 2 0 0 1 0-3.04l1.3-1.1a8 8 0 0 0-1.25-2.16l-1.6.58a2 2 0 0 1-2.63-1.53l-.3-1.67a8 8 0 0 0-2.5 0l-.3 1.67A2 2 0 0 1 5.81 5.8l-1.6-.58a8 8 0 0 0-1.24 2.16M7.5 10a2.5 2.5 0 1 1 5 0 2.5 2.5 0 0 1-5 0m1 0a1.5 1.5 0 1 0 3 0 1.5 1.5 0 0 0-3 0\"/>",
  "delete": "<path d=\"M8.5 4h3a1.5 1.5 0 0 0-3 0m-1 0a2.5 2.5 0 0 1 5 0h5a.5.5 0 0 1 0 1h-1.05l-1.2 10.34A3 3 0 0 1 12.27 18H7.73a3 3 0 0 1-2.98-2.66L3.55 5H2.5a.5.5 0 0 1 0-1zM5.74 15.23A2 2 0 0 0 7.73 17h4.54a2 2 0 0 0 1.99-1.77L15.44 5H4.56zM8.5 7.5c.28 0 .5.22.5.5v6a.5.5 0 0 1-1 0V8c0-.28.22-.5.5-.5M12 8a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0z\"/>",
  "add": "<path d=\"M10 2.5c.28 0 .5.22.5.5v6.5H17a.5.5 0 0 1 0 1h-6.5V17a.5.5 0 0 1-1 0v-6.5H3a.5.5 0 0 1 0-1h6.5V3c0-.28.22-.5.5-.5\"/>",
  "edit": "<path d=\"M17.18 2.93a2.97 2.97 0 0 0-4.26-.06l-9.37 9.38q-.5.5-.66 1.2l-.88 3.94a.5.5 0 0 0 .6.6l3.93-.87c.46-.1.9-.34 1.23-.68l9.36-9.36a2.97 2.97 0 0 0 .05-4.15m-3.55.65a1.97 1.97 0 1 1 2.8 2.8l-.68.66-2.8-2.79zm-1.38 1.38 2.8 2.8-7.99 7.97q-.31.31-.74.41l-3.16.7.7-3.18q.1-.41.4-.7z\"/>",
  "search": "<path d=\"M13.73 14.44a6.5 6.5 0 1 1 .7-.7l3.42 3.4a.5.5 0 0 1-.63.77l-.07-.06zm-.71-.71A5.5 5.5 0 0 0 15 9.5a5.5 5.5 0 1 0-1.98 4.23\"/>",
  "filter": "<path d=\"M7.5 13h5a.5.5 0 0 1 .09 1H7.5a.5.5 0 0 1-.09-1zh5zm-2-4h9a.5.5 0 0 1 .09 1H5.5a.5.5 0 0 1-.09-1zh9zm-2-4h13a.5.5 0 0 1 .09 1H3.5a.5.5 0 0 1-.09-1zh13z\"/>",
  "sun": "<path d=\"M10 2c.28 0 .5.22.5.5v1a.5.5 0 0 1-1 0v-1c0-.28.22-.5.5-.5m0 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8m0-1a3 3 0 1 1 0-6 3 3 0 0 1 0 6m7.5-2.5a.5.5 0 0 0 0-1h-1a.5.5 0 0 0 0 1zM10 16c.28 0 .5.22.5.5v1a.5.5 0 0 1-1 0v-1c0-.28.22-.5.5-.5m-6.5-5.5a.5.5 0 0 0 0-1H2.46a.5.5 0 0 0 0 1zm.65-6.35c.2-.2.5-.2.7 0l1 1a.5.5 0 1 1-.7.7l-1-1a.5.5 0 0 1 0-.7m.7 11.7a.5.5 0 0 1-.7-.7l1-1a.5.5 0 0 1 .7.7zm11-11.7a.5.5 0 0 0-.7 0l-1 1a.5.5 0 0 0 .7.7l1-1a.5.5 0 0 0 0-.7m-.7 11.7a.5.5 0 0 0 .7-.7l-1-1a.5.5 0 0 0-.7.7z\"/>",
  "moon": "<path d=\"M15.5 13.5A6.98 6.98 0 0 1 4 14.39c2.83-1.09 4.56-2.42 5.6-4.4 1.04-2 1.33-4.16.75-6.9q1.36.17 2.58.87a7 7 0 0 1 2.55 9.54M5.45 16.92A7.98 7.98 0 1 0 9.88 2.04a.6.6 0 0 0-.61.73c.69 2.82.43 4.88-.55 6.76-.94 1.78-2.55 3.03-5.55 4.1a.6.6 0 0 0-.3.9 8 8 0 0 0 2.59 2.39\"/>",
  "globe": "<path d=\"M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16m0-15c.66 0 1.4.59 2.02 1.9q.33.71.56 1.6H7.42q.23-.89.56-1.6C8.59 3.6 9.34 3 10 3M7.07 4.49q-.4.9-.68 2.01H3.94A7 7 0 0 1 7.7 3.38q-.36.5-.64 1.1M6.2 7.5a16 16 0 0 0 0 5H3.46a7 7 0 0 1 0-5zm.2 6q.26 1.12.68 2.01.28.61.64 1.1a7 7 0 0 1-3.77-3.11zm1.03 0h5.16a9 9 0 0 1-.56 1.6C11.41 16.4 10.66 17 10 17s-1.4-.59-2.02-1.9q-.33-.71-.56-1.6m5.37-1H7.21a15 15 0 0 1 0-5h5.58a15 15 0 0 1 0 5m.82 1h2.45a7 7 0 0 1-3.77 3.12q.36-.5.64-1.1.4-.9.68-2.02m2.93-1h-2.73a16 16 0 0 0 0-5h2.73a7 7 0 0 1 0 5m-4.25-9.12a7 7 0 0 1 3.77 3.12h-2.45a11 11 0 0 0-.68-2.01q-.28-.61-.64-1.1\"/>",
  "history": "<path d=\"M10 4a6 6 0 1 1-5.98 5.54.5.5 0 1 0-1-.08L3 10a7 7 0 1 0 2-4.9V3.5a.5.5 0 0 0-1 0v3c0 .28.22.5.5.5h3a.5.5 0 0 0 0-1H5.53c1.1-1.23 2.7-2 4.47-2m0 2.5a.5.5 0 0 0-1 0v4c0 .28.22.5.5.5h3a.5.5 0 0 0 0-1H10z\"/>",
  "document": "<path d=\"M6 2a2 2 0 0 0-2 2v12c0 1.1.9 2 2 2h8a2 2 0 0 0 2-2V7.41c0-.4-.16-.78-.44-1.06l-3.91-3.91A1.5 1.5 0 0 0 10.59 2zM5 4a1 1 0 0 1 1-1h4v3.5c0 .83.67 1.5 1.5 1.5H15v8a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1zm9.8 3h-3.3a.5.5 0 0 1-.5-.5V3.2z\"/>",
  "document-text": "<path d=\"M6.5 10a.5.5 0 0 0 0 1h7a.5.5 0 0 0 0-1zm0 2a.5.5 0 0 0 0 1h7a.5.5 0 0 0 0-1zm0 2a.5.5 0 0 0 0 1h7a.5.5 0 0 0 0-1zM4 4c0-1.1.9-2 2-2h4.59q.62.01 1.06.44l3.91 3.91c.28.28.44.67.44 1.06V16a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2zm2-1a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V8h-3.5A1.5 1.5 0 0 1 10 6.5V3zm5.5 4h3.3L11 3.2v3.3c0 .28.22.5.5.5\"/>",
  "print": "<path d=\"M5 4.5C5 3.67 5.67 3 6.5 3h7c.83 0 1.5.67 1.5 1.5V5h.5A2.5 2.5 0 0 1 18 7.5v5c0 .83-.67 1.5-1.5 1.5H15v1.5c0 .83-.67 1.5-1.5 1.5h-7A1.5 1.5 0 0 1 5 15.5V14H3.5A1.5 1.5 0 0 1 2 12.5v-5A2.5 2.5 0 0 1 4.5 5H5zM6 5h8v-.5a.5.5 0 0 0-.5-.5h-7a.5.5 0 0 0-.5.5zm-1 8v-1.5c0-.83.67-1.5 1.5-1.5h7c.83 0 1.5.67 1.5 1.5V13h1.5a.5.5 0 0 0 .5-.5v-5c0-.83-.67-1.5-1.5-1.5h-11C3.67 6 3 6.67 3 7.5v5c0 .28.22.5.5.5zm1.5-2a.5.5 0 0 0-.5.5v4c0 .28.22.5.5.5h7a.5.5 0 0 0 .5-.5v-4a.5.5 0 0 0-.5-.5z\"/>",
  "sign-out": "<path d=\"M8.5 11.25a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5M11 3.5a.5.5 0 0 0-.58-.5l-7 1.08a.5.5 0 0 0-.42.49v10.86c0 .25.18.46.42.5l7 1.07a.5.5 0 0 0 .58-.5V10h5.17l-1 .87a.5.5 0 0 0 .66.76l2-1.75a.5.5 0 0 0 0-.76l-2-1.75a.5.5 0 1 0-.65.76l1 .87H11zm-1 .58v11.84L4 15V5zM12.5 16H12v-5h1v4.5a.5.5 0 0 1-.5.5M12 8V4h.5c.28 0 .5.22.5.5V8z\"/>",
  "password": "<path d=\"M7.85 8.15a.5.5 0 0 0-.7 0l-.65.64-.65-.64a.5.5 0 1 0-.7.7l.64.65-.64.65a.5.5 0 0 0 .7.7l.65-.64.65.64a.5.5 0 0 0 .7-.7l-.64-.65.64-.65a.5.5 0 0 0 0-.7m3.3 0a.5.5 0 0 1 .7.7l-.64.65.64.65a.5.5 0 0 1-.7.7l-.65-.64-.65.64a.5.5 0 0 1-.7-.7l.64-.65-.64-.65a.5.5 0 1 1 .7-.7l.65.64zM13.5 10a.5.5 0 0 0 0 1h2a.5.5 0 0 0 0-1zM4.75 4A2.75 2.75 0 0 0 2 6.75v5.5A2.75 2.75 0 0 0 4.75 15h10.5A2.75 2.75 0 0 0 18 12.25v-5.5A2.75 2.75 0 0 0 15.25 4zM3 6.75C3 5.78 3.78 5 4.75 5h10.5c.97 0 1.75.78 1.75 1.75v5.5c0 .97-.78 1.75-1.75 1.75H4.75C3.78 14 3 13.22 3 12.25z\"/>",
  "camera": "<path d=\"M10 6a4 4 0 1 0 0 8 4 4 0 0 0 0-8m-3 4a3 3 0 1 1 6 0 3 3 0 0 1-6 0m1.12-8a1.5 1.5 0 0 0-1.34.83L6.2 4H4.5A2.5 2.5 0 0 0 2 6.5v8A2.5 2.5 0 0 0 4.5 17h11a2.5 2.5 0 0 0 2.5-2.5v-8A2.5 2.5 0 0 0 15.5 4h-1.69l-.58-1.17A1.5 1.5 0 0 0 11.89 2zm-.44 1.28A.5.5 0 0 1 8.12 3h3.77q.3 0 .45.28l.72 1.44a.5.5 0 0 0 .45.28h2c.82 0 1.5.67 1.5 1.5v8c0 .83-.68 1.5-1.5 1.5h-11A1.5 1.5 0 0 1 3 14.5v-8C3 5.67 3.67 5 4.5 5h2a.5.5 0 0 0 .44-.28z\"/>",
  "dev-tools": "<path d=\"M3 6a3 3 0 0 1 3-3h8a3 3 0 0 1 3 3v2.03a5 5 0 0 0-1 0V7H4v7c0 1.1.9 2 2 2h3.5q-.35.46-.45 1H6a3 3 0 0 1-3-3zm10.04 3.59L11.6 8.15a.5.5 0 0 0-.7.7l1.57 1.58q.24-.45.57-.84M6 4a2 2 0 0 0-2 2h12a2 2 0 0 0-2-2zm3.1 4.85a.5.5 0 1 0-.7-.7l-2.5 2.5a.5.5 0 0 0 0 .7l2.5 2.5a.5.5 0 0 0 .7-.7L6.96 11zm7.8.17c.36.05.46.48.2.75l-.97.97a1.5 1.5 0 1 0 2.13 2.13l.97-.97c.27-.26.7-.16.75.2a3.5 3.5 0 0 1-4.68 3.73l-2.73 2.73a1.5 1.5 0 1 1-2.13-2.13l2.73-2.73a3.52 3.52 0 0 1 3.72-4.68\"/>",
  "code": "<path d=\"M12.64 1.02a.5.5 0 0 1 .34.62l-5 17a.5.5 0 0 1-.96-.28l5-17a.5.5 0 0 1 .62-.34M5.13 5.17a.5.5 0 0 1 .74.66L2.17 10l3.7 4.17a.5.5 0 0 1-.74.66l-4-4.5a.5.5 0 0 1 0-.66zm9.04-.04a.5.5 0 0 1 .7.04l4 4.5a.5.5 0 0 1 0 .66l-4 4.5a.5.5 0 0 1-.74-.66l3.7-4.17-3.7-4.17a.5.5 0 0 1 .04-.7\"/>",
  "plug-connected": "<path d=\"M17.85 2.85a.5.5 0 0 0-.7-.7L14.48 4.8a4.04 4.04 0 0 0-5.33.34l-.3.3a1.5 1.5 0 0 0 0 2.1l3.6 3.6c.58.59 1.52.59 2.1 0l.3-.3a4.04 4.04 0 0 0 .34-5.33zm-4 7.6c-.2.19-.5.19-.7 0l-3.6-3.6c-.19-.2-.19-.5 0-.7l.3-.3a3.04 3.04 0 0 1 4.3 4.3zm-6.3-1.6a1.5 1.5 0 0 0-2.1 0l-.3.3a4.04 4.04 0 0 0-.34 5.33l-2.66 2.67a.5.5 0 0 0 .7.7l2.67-2.66a4.04 4.04 0 0 0 5.33-.34l.3-.3c.59-.58.59-1.52 0-2.1zm-1.4.7c.2-.19.5-.19.7 0l3.6 3.6c.19.2.19.5 0 .7l-.3.3a3.04 3.04 0 1 1-4.3-4.3z\"/>",
  "link": "<path d=\"M8 6a.5.5 0 0 1 .09 1H6a3 3 0 0 0-.2 6H8a.5.5 0 0 1 .09 1H6a4 4 0 0 1-.22-8H8m6 0a4 4 0 0 1 .22 8H12a.5.5 0 0 1-.09-1H14a3 3 0 0 0 .2-6H12a.5.5 0 0 1-.09-1H14M6 9.5h8a.5.5 0 0 1 .09 1H6a.5.5 0 0 1-.09-1zh8z\"/>",
  "clock": "<path d=\"M10 2a8 8 0 1 1 0 16 8 8 0 0 1 0-16m0 1a7 7 0 1 0 0 14 7 7 0 0 0 0-14m-.5 2a.5.5 0 0 1 .5.41V10h2.5a.5.5 0 0 1 .09 1H9.5a.5.5 0 0 1-.5-.41V5.5c0-.28.22-.5.5-.5\"/>",
  "open": "<path d=\"M6 4a2 2 0 0 0-2 2v8c0 1.1.9 2 2 2h8a2 2 0 0 0 2-2v-2.5a.5.5 0 0 1 1 0V14a3 3 0 0 1-3 3H6a3 3 0 0 1-3-3V6a3 3 0 0 1 3-3h2.5a.5.5 0 0 1 0 1zm5-.5c0-.28.22-.5.5-.5h5c.28 0 .5.22.5.5v5a.5.5 0 0 1-1 0V4.7l-4.15 4.15a.5.5 0 0 1-.7-.7L15.29 4H11.5a.5.5 0 0 1-.5-.5\"/>",
  "certificate": "<path d=\"M4 3a2 2 0 0 0-2 2v3.67q.43-.53 1-.91V5a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H9.24l-.24.33V15h7a2 2 0 0 0 2-2V5a2 2 0 0 0-2-2zm1 3.5c0-.28.22-.5.5-.5h9a.5.5 0 0 1 0 1h-9a.5.5 0 0 1-.5-.5m.5 8.5a3.5 3.5 0 1 1 0-7 3.5 3.5 0 0 1 0 7m-2.5.24a4.5 4.5 0 0 0 5 0V18a.5.5 0 0 1-.8.4l-1.4-1.05a.5.5 0 0 0-.6 0L3.8 18.4A.5.5 0 0 1 3 18zM10.5 10a.5.5 0 0 0 0 1h4a.5.5 0 0 0 0-1z\"/>",
  "fingerprint": "<path d=\"M6.72 3.95c1.53-.74 4.81-1.44 8.5.97a.5.5 0 1 0 .55-.84c-4.03-2.63-7.7-1.9-9.49-1.03a.5.5 0 1 0 .44.9m-1.81.64a.5.5 0 0 1-.14.7 5 5 0 0 0-1.34 1.46.5.5 0 0 1-.86-.5c.27-.46.95-1.34 1.65-1.8a.5.5 0 0 1 .69.14m5.59-.05a.5.5 0 1 0 0 1c1.66 0 5.51 1.38 6.5 6.55a.5.5 0 0 0 1-.18c-1.1-5.72-5.43-7.37-7.5-7.37M9.34 10.8c-.87.7-1.52 2.69.56 6.46a.5.5 0 0 1-.87.48c-2.15-3.88-1.78-6.52-.32-7.71A2.68 2.68 0 0 1 13 11.35q.11.4.2.9l.04.15q.11.57.3 1.18c.26.79.67 1.57 1.48 2.16a.5.5 0 1 1-.6.8 5 5 0 0 1-1.83-2.65q-.22-.7-.33-1.29l-.03-.16-.19-.8a1.68 1.68 0 0 0-2.7-.84m6.16 1.17a.5.5 0 1 0-1 .06c.1 1.8 1.22 2.74 1.85 2.95a.5.5 0 0 0 .3-.96c-.22-.07-1.07-.64-1.15-2.05m-4.5.53a.5.5 0 1 0-1 0c0 1.04.13 1.85.44 2.64.3.77.77 1.5 1.4 2.4a.5.5 0 1 0 .82-.58 11 11 0 0 1-1.3-2.19A6 6 0 0 1 11 12.5M7.97 8.79c-1.72 1.33-2.7 4.14-1.02 7.49a.5.5 0 0 1-.9.44C4.18 13 5.22 9.65 7.35 8a4.8 4.8 0 0 1 3.73-1 5.5 5.5 0 0 1 3.65 2.56.5.5 0 1 1-.84.55 4.5 4.5 0 0 0-2.97-2.12 3.8 3.8 0 0 0-2.95.8m.49-3a.5.5 0 0 0-.35-.94c-4.68 1.7-5.79 6.19-5.35 9.22a.5.5 0 0 0 .99-.14c-.4-2.74.62-6.65 4.7-8.14\"/>",
  "scales": "<path d=\"M3.5 3a.5.5 0 1 0 0 1h.75L2.08 9.22a1 1 0 0 0-.08.4 3 3 0 0 0 6 0 1 1 0 0 0-.08-.4L5.75 4H9.5v10H6a2 2 0 1 0 0 4h8a2 2 0 0 0 0-4h-3.5V4h3.75l-2.17 5.22a1 1 0 0 0-.08.4 3 3 0 0 0 6 0 1 1 0 0 0-.08-.4L15.75 4h.75a.5.5 0 0 0 0-1zM5 11.5A2 2 0 0 1 3.06 10h3.88A2 2 0 0 1 5 11.5m0-6.7L6.75 9h-3.5zM6 15h8a1 1 0 0 1 0 2H6a1 1 0 1 1 0-2m10.75-6h-3.5L15 4.8zm-3.69 1h3.88a2 2 0 0 1-3.88 0\"/>",
  "book-open": "<path d=\"M10 16c-.46.6-1.18 1-2 1H3.5A1.5 1.5 0 0 1 2 15.5v-11C2 3.67 2.67 3 3.5 3H8c.82 0 1.54.4 2 1 .46-.6 1.18-1 2-1h4.5c.83 0 1.5.67 1.5 1.5v11c0 .83-.67 1.5-1.5 1.5H12a2.5 2.5 0 0 1-2-1M3 4.5v11c0 .28.22.5.5.5H8c.83 0 1.5-.67 1.5-1.5v-9C9.5 4.67 8.83 4 8 4H3.5a.5.5 0 0 0-.5.5m7.5 10c0 .83.67 1.5 1.5 1.5h4.5a.5.5 0 0 0 .5-.5v-11a.5.5 0 0 0-.5-.5H12c-.83 0-1.5.67-1.5 1.5z\"/>",
  "building": "<path d=\"M6.75 6.5a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5m.75 2.25a.75.75 0 1 1-1.5 0 .75.75 0 0 1 1.5 0m-.75 3.75a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5m3.75-6.75a.75.75 0 1 1-1.5 0 .75.75 0 0 1 1.5 0M9.75 9.5a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5m.75 2.25a.75.75 0 1 1-1.5 0 .75.75 0 0 1 1.5 0m2.25.75a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5M4.5 18a.5.5 0 0 1-.5-.5v-14C4 2.67 4.67 2 5.5 2h6c.83 0 1.5.67 1.5 1.5V8h1.5c.83 0 1.5.67 1.5 1.5v8a.5.5 0 0 1-.5.5zM5 3.5V17h2v-2.5c0-.28.22-.5.5-.5h5c.28 0 .5.22.5.5V17h2V9.5a.5.5 0 0 0-.5-.5h-2a.5.5 0 0 1-.5-.5v-5a.5.5 0 0 0-.5-.5h-6a.5.5 0 0 0-.5.5M12 15h-1.5v2H12zm-2.5 0H8v2h1.5z\"/>",
  "navigation": "<path d=\"M2 4.5c0-.28.22-.5.5-.5h15a.5.5 0 0 1 0 1h-15a.5.5 0 0 1-.5-.5m0 5c0-.28.22-.5.5-.5h15a.5.5 0 0 1 0 1h-15a.5.5 0 0 1-.5-.5m.5 4.5a.5.5 0 0 0 0 1h15a.5.5 0 0 0 0-1z\"/>",
  "flash": "<path d=\"M6.2 2.77C6.31 2.31 6.73 2 7.2 2h5.25c.73 0 1.24.71 1 1.4L12.22 7h2.56c.95 0 1.4 1.14.77 1.81l-8.68 8.86c-.76.79-2.06.06-1.8-1L6.23 12H4.96c-.7 0-1.21-.68-1.02-1.36zM7.2 3a.1.1 0 0 0-.06.05L4.9 10.92q0 .07.06.08h1.91a.5.5 0 0 1 .49.62l-1.33 5.3v.04l.03.03.04.01h.01l.03-.02 8.68-8.86.01-.03v-.05l-.03-.03-.03-.01H11.5a.5.5 0 0 1-.47-.67l1.5-4.25a.06.06 0 0 0-.07-.08z\"/>",
  "play": "<path d=\"M17.22 8.69a1.5 1.5 0 0 1 0 2.62l-10 5.5A1.5 1.5 0 0 1 5 15.5v-11A1.5 1.5 0 0 1 7.22 3.2zm-.48 1.75a.5.5 0 0 0 0-.88l-10-5.5A.5.5 0 0 0 6 4.5v11c0 .38.4.62.74.44z\"/>"
};

    function icon(name, options) {
        var opts = typeof options === "string" ? { className: options } : (options || {});
        var inner = FLUENT_ICONS[name] || FLUENT_ICONS["shield-checkmark"] || "";
        var cls = "fluent-icon" + (opts.className ? " " + opts.className : "");
        var sizeAttr = opts.size ? " width=\"" + Number(opts.size) + "\" height=\"" + Number(opts.size) + "\"" : "";
        return "<svg class=\"" + escapeHtml(cls) + "\"" + sizeAttr + " viewBox=\"0 0 20 20\" fill=\"currentColor\" aria-hidden=\"true\">" + inner + "</svg>";
    }

    window.GilosIcons = FLUENT_ICONS;

    var toastContainer = null;

    function escapeHtml(value) {
        if (value === null || value === undefined) return '';
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function ensureToastContainer() {
        if (toastContainer && document.body.contains(toastContainer)) {
            return toastContainer;
        }
        toastContainer = document.createElement('div');
        toastContainer.className = 'gilos-toast-region';
        toastContainer.setAttribute('aria-live', 'polite');
        toastContainer.setAttribute('aria-atomic', 'false');
        document.body.appendChild(toastContainer);
        return toastContainer;
    }

    function getToastIcon(type) {
        switch (type) {
            case 'success':
                return icon('checkmark-circle', { className: 'gilos-toast-icon', size: 18 });
            case 'error':
                return icon('error-circle', { className: 'gilos-toast-icon', size: 18 });
            case 'warning':
                return icon('warning', { className: 'gilos-toast-icon', size: 18 });
            default:
                return icon('info', { className: 'gilos-toast-icon', size: 18 });
        }
    }

    function toast(message, type, durationMs) {
        if (!message) return;
        var kind = type || 'info';
        var duration = typeof durationMs === 'number' ? durationMs : (kind === 'error' ? 4500 : 3200);
        var container = ensureToastContainer();

        var el = document.createElement('div');
        el.className = 'gilos-toast gilos-toast--' + kind;
        el.setAttribute('role', kind === 'error' ? 'alert' : 'status');
        el.innerHTML =
            getToastIcon(kind) +
            '<div class="gilos-toast-body">' + escapeHtml(message) + '</div>' +
            '<button type="button" class="gilos-toast-close" aria-label="Dismiss">' +
                '' + icon('dismiss', { size: 14 }) + '' +
            '</button>';

        var dismiss = function () {
            if (!el.parentNode || el.classList.contains('is-leaving')) return;
            el.classList.add('is-leaving');
            window.setTimeout(function () {
                if (el.parentNode) el.parentNode.removeChild(el);
            }, 170);
        };

        el.querySelector('.gilos-toast-close').addEventListener('click', dismiss);
        container.appendChild(el);

        while (container.children.length > 4) {
            container.removeChild(container.firstChild);
        }

        if (duration > 0) {
            var remaining = duration;
            var startedAt = Date.now();
            var timerId = null;

            var startTimer = function () {
                if (timerId !== null || remaining <= 0) return;
                startedAt = Date.now();
                timerId = window.setTimeout(dismiss, remaining);
            };

            var pauseTimer = function () {
                if (timerId === null) return;
                window.clearTimeout(timerId);
                timerId = null;
                remaining = Math.max(0, remaining - (Date.now() - startedAt));
            };

            el.addEventListener('mouseenter', pauseTimer);
            el.addEventListener('focusin', pauseTimer);
            el.addEventListener('mouseleave', startTimer);
            el.addEventListener('focusout', function (e) {
                if (!el.contains(e.relatedTarget)) {
                    startTimer();
                }
            });

            startTimer();
        }
    }

    function copyText(text, options) {
        var opts = options || {};
        var successMsg = opts.successMsg || 'Copied to clipboard';
        var errorMsg = opts.errorMsg || 'Failed to copy';

        function onCopied() {
            if (opts.triggerEl) {
                var btn = opts.triggerEl;
                if (!btn.dataset.origHtml) {
                    btn.dataset.origHtml = btn.innerHTML;
                }
                btn.classList.add('is-copied');
                if (opts.copiedHtml) {
                    btn.innerHTML = opts.copiedHtml;
                }
                window.setTimeout(function () {
                    btn.classList.remove('is-copied');
                    if (opts.copiedHtml && btn.dataset.origHtml) {
                        btn.innerHTML = btn.dataset.origHtml;
                    }
                }, 1600);
            }
            if (!opts.silent) {
                toast(successMsg, 'success', 2200);
            }
            return true;
        }

        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(String(text)).then(onCopied).catch(function () {
                return fallbackCopy(String(text)) ? onCopied() : (toast(errorMsg, 'error'), false);
            });
        }
        return Promise.resolve(fallbackCopy(String(text)) ? onCopied() : (toast(errorMsg, 'error'), false));
    }

    function fallbackCopy(text) {
        try {
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.left = '-9999px';
            ta.style.top = '-9999px';
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            var ok = document.execCommand('copy');
            document.body.removeChild(ta);
            return ok;
        } catch (e) {
            return false;
        }
    }

    function setButtonLoading(btn, isLoading, loadingText) {
        if (!btn) return;
        if (isLoading) {
            if (!btn.dataset.origContent) {
                btn.dataset.origContent = btn.innerHTML;
            }
            btn.disabled = true;
            btn.setAttribute('aria-busy', 'true');
            var label = loadingText || btn.textContent.trim();
            btn.innerHTML = '<span class="btn-spinner" aria-hidden="true"></span><span>' + escapeHtml(label) + '</span>';
        } else {
            btn.disabled = false;
            btn.removeAttribute('aria-busy');
            if (btn.dataset.origContent) {
                btn.innerHTML = btn.dataset.origContent;
                delete btn.dataset.origContent;
            }
        }
    }

    function parseUserAgent(ua) {
        if (!ua || typeof ua !== 'string') {
            return { browser: '', os: '', deviceType: 'desktop', shortLabel: '', raw: '' };
        }
        var lower = ua.toLowerCase();

        var isBot = /curl|wget|postman|insomnia|httpie|python-requests|go-http-client|okhttp|axios|bot|crawler|spider/.test(lower);
        var deviceType = 'desktop';
        if (isBot) {
            deviceType = 'api';
        } else if (/ipad|tablet|playbook|silk|(android(?!.*mobile))/.test(lower)) {
            deviceType = 'tablet';
        } else if (/mobile|iphone|ipod|android|blackberry|iemobile|opera mini/.test(lower)) {
            deviceType = 'mobile';
        }

        var browser = '';
        if (/edg\/|edge\/|edgios|edga/.test(lower)) browser = 'Microsoft Edge';
        else if (/opr\/|opera/.test(lower)) browser = 'Opera';
        else if (/samsungbrowser/.test(lower)) browser = 'Samsung Internet';
        else if (/yabrowser/.test(lower)) browser = 'Yandex Browser';
        else if (/vivaldi/.test(lower)) browser = 'Vivaldi';
        else if (/firefox|fxios/.test(lower)) browser = 'Firefox';
        else if (/crios|chrome/.test(lower) && !/chromium/.test(lower)) browser = 'Chrome';
        else if (/safari/.test(lower) && !/chrome|crios|chromium/.test(lower)) browser = 'Safari';
        else if (/go-http-client/.test(lower)) browser = 'Go HTTP Client';
        else if (/curl/.test(lower)) browser = 'cURL';
        else if (/postman/.test(lower)) browser = 'Postman';
        else if (/okhttp/.test(lower)) browser = 'Android Client';

        var os = '';
        if (/iphone/.test(lower)) os = 'iPhone';
        else if (/ipad/.test(lower)) os = 'iPad';
        else if (/android/.test(lower)) os = 'Android';
        else if (/mac os x|macintosh/.test(lower)) os = 'macOS';
        else if (/windows nt/.test(lower)) os = 'Windows';
        else if (/cros/.test(lower)) os = 'ChromeOS';
        else if (/linux/.test(lower)) os = 'Linux';

        var parts = [];
        if (browser) parts.push(browser);
        if (os) parts.push(os);
        var shortLabel = parts.length ? parts.join(' on ') : ua.slice(0, 48);

        return {
            browser: browser,
            os: os,
            deviceType: deviceType,
            shortLabel: shortLabel,
            raw: ua
        };
    }

    function getDeviceIconSvg(deviceType, size) {
        var s = size || 18;
        switch (deviceType) {
            case 'mobile':
                return icon('phone', { size: s });
            case 'tablet':
                return icon('tablet', { size: s });
            case 'api':
                return icon('code', { size: s });
            default:
                return icon('desktop', { size: s });
        }
    }

    function formatRelativeTime(dateString, T) {
        var labels = T || {};
        if (!dateString) return labels.na || 'N/A';
        var date = new Date(dateString);
        if (isNaN(date.getTime())) return labels.na || 'N/A';

        var diffSec = Math.floor((Date.now() - date.getTime()) / 1000);
        if (diffSec < 60) return labels.just_now || 'just now';
        var diffMin = Math.floor(diffSec / 60);
        if (diffMin < 60) {
            return diffMin === 1 ? (labels.minute_ago || '1m ago') : diffMin + ' ' + (labels.minutes_ago || 'minutes ago');
        }
        var diffHr = Math.floor(diffMin / 60);
        if (diffHr < 24) {
            return diffHr === 1 ? (labels.hour_ago || '1h ago') : diffHr + ' ' + (labels.hours_ago || 'hours ago');
        }
        var diffDay = Math.floor(diffHr / 24);
        if (diffDay < 30) {
            return diffDay === 1 ? (labels.day_ago || '1d ago') : diffDay + ' ' + (labels.days_ago || 'days ago');
        }
        var diffMonth = Math.floor(diffDay / 30);
        if (diffMonth < 12) {
            return diffMonth === 1 ? (labels.month_ago || '1 month ago') : diffMonth + ' ' + (labels.months_ago || 'months ago');
        }
        return date.toLocaleDateString(document.documentElement.lang || 'en', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    }

    function formatExactTime(dateString) {
        if (!dateString) return '';
        var date = new Date(dateString);
        if (isNaN(date.getTime())) return '';
        return date.toLocaleString(document.documentElement.lang || 'en', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    function evaluatePassword(pw) {
        var val = typeof pw === 'string' ? pw : '';
        var rules = {
            length: val.length >= 8 && val.length <= 72,
            upperLower: /[a-z]/.test(val) && /[A-Z]/.test(val),
            number: /[0-9]/.test(val),
            special: /[^A-Za-z0-9]/.test(val)
        };

        if (!val.length) {
            return { score: 0, rules: rules };
        }

        var score = 1;
        if (rules.length) {
            var checks = (rules.upperLower ? 1 : 0) + (rules.number ? 1 : 0) + (rules.special ? 1 : 0);
            if (val.length >= 12 && checks >= 2) {
                score = 4;
            } else if (checks >= 2) {
                score = 3;
            } else if (checks >= 1 || val.length >= 10) {
                score = 2;
            } else {
                score = 1;
            }
        }
        return { score: score, rules: rules };
    }

    function attachPasswordStrength(inputEl, containerEl, T) {
        if (!inputEl || !containerEl) return function () {};
        var t = T || {};

        var checkIcon = '<svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';

        containerEl.innerHTML =
            '<div class="pw-strength">' +
                '<div class="pw-strength-header">' +
                    '<span>' + escapeHtml(t.password_strength || 'Password strength') + '</span>' +
                    '<span class="pw-strength-label" data-level="0"></span>' +
                '</div>' +
                '<div class="pw-strength-bars" data-level="0">' +
                    '<span class="pw-strength-segment"></span>' +
                    '<span class="pw-strength-segment"></span>' +
                    '<span class="pw-strength-segment"></span>' +
                    '<span class="pw-strength-segment"></span>' +
                '</div>' +
                '<div class="pw-rules">' +
                    '<span class="pw-rule" data-rule="length"><span class="pw-rule-dot">' + checkIcon + '</span>' + escapeHtml(t.password_min_8 || '8-72 characters') + '</span>' +
                    '<span class="pw-rule" data-rule="upperLower"><span class="pw-rule-dot">' + checkIcon + '</span>' + escapeHtml(t.pw_rule_case || 'Upper & lowercase') + '</span>' +
                    '<span class="pw-rule" data-rule="number"><span class="pw-rule-dot">' + checkIcon + '</span>' + escapeHtml(t.pw_rule_number || 'Number (0-9)') + '</span>' +
                    '<span class="pw-rule" data-rule="special"><span class="pw-rule-dot">' + checkIcon + '</span>' + escapeHtml(t.pw_rule_symbol || 'Special character') + '</span>' +
                '</div>' +
            '</div>';

        var labelEl = containerEl.querySelector('.pw-strength-label');
        var barsEl = containerEl.querySelector('.pw-strength-bars');
        var ruleEls = {
            length: containerEl.querySelector('[data-rule="length"]'),
            upperLower: containerEl.querySelector('[data-rule="upperLower"]'),
            number: containerEl.querySelector('[data-rule="number"]'),
            special: containerEl.querySelector('[data-rule="special"]')
        };

        var levelNames = {
            0: '',
            1: t.pw_strength_weak || 'Weak',
            2: t.pw_strength_fair || 'Fair',
            3: t.pw_strength_good || 'Good',
            4: t.pw_strength_strong || 'Strong'
        };

        function update() {
            var res = evaluatePassword(inputEl.value);
            barsEl.setAttribute('data-level', String(res.score));
            labelEl.setAttribute('data-level', String(res.score));
            labelEl.textContent = levelNames[res.score] || '';

            Object.keys(ruleEls).forEach(function (key) {
                if (ruleEls[key]) {
                    ruleEls[key].classList.toggle('is-met', Boolean(res.rules[key]));
                }
            });
        }

        inputEl.addEventListener('input', update);
        update();
        return update;
    }

    function getFocusableElements(container) {
        if (!container || typeof container.querySelectorAll !== 'function') return [];
        var candidates = container.querySelectorAll(
            'button:not([disabled]), [href], input:not([type="hidden"]):not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
        );
        return Array.prototype.filter.call(candidates, function (el) {
            if (!el) return false;
            if (el.hidden) return false;
            if (typeof window.getComputedStyle === 'function' && el.style) {
                if (el.style.display === 'none' || el.style.visibility === 'hidden') return false;
            }
            return el.offsetParent === undefined || el.offsetParent !== null || el === document.activeElement;
        });
    }

    function bindModalA11y(modalEl, closeFn, options) {
        if (!modalEl || typeof closeFn !== 'function') return;
        if (modalEl.dataset && modalEl.dataset.a11yBound === '1') return;
        if (modalEl.dataset) modalEl.dataset.a11yBound = '1';
        var opts = options || {};
        if (opts.closeOnBackdrop !== false) {
            modalEl.addEventListener('click', function (e) {
                if (e.target === modalEl) {
                    closeFn();
                }
            });
        }
        document.addEventListener('keydown', function (e) {
            if (!modalEl.classList.contains('is-open')) return;
            if (document.querySelector('.swal2-container')) return;
            var openModals = document.querySelectorAll('.modal.is-open');
            if (openModals.length && openModals[openModals.length - 1] !== modalEl) return;

            if (e.key === 'Escape' && opts.closeOnEscape !== false) {
                e.preventDefault();
                closeFn();
                return;
            }

            if (e.key === 'Tab') {
                var focusables = getFocusableElements(modalEl);
                if (!focusables.length) return;
                var first = focusables[0];
                var last = focusables[focusables.length - 1];
                var active = document.activeElement;
                if (e.shiftKey) {
                    if (!modalEl.contains || !modalEl.contains(active) || active === first) {
                        e.preventDefault();
                        if (typeof last.focus === 'function') last.focus();
                    }
                } else {
                    if (!modalEl.contains || !modalEl.contains(active) || active === last) {
                        e.preventDefault();
                        if (typeof first.focus === 'function') first.focus();
                    }
                }
            }
        });
    }

    function attachCapsLockWarning(inputEl, badgeEl, labelText) {
        if (!inputEl || !badgeEl) return;
        if (labelText && !badgeEl.firstElementChild && !badgeEl.textContent.trim()) {
            badgeEl.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg><span>' + escapeHtml(labelText) + '</span>';
        }
        badgeEl.hidden = true;
        function update(e) {
            if (!e || typeof e.getModifierState !== 'function') return;
            var active = !!e.getModifierState('CapsLock');
            badgeEl.hidden = !active;
            badgeEl.classList.toggle('is-visible', active);
        }
        inputEl.addEventListener('keydown', update);
        inputEl.addEventListener('keyup', update);
        inputEl.addEventListener('blur', function () {
            badgeEl.hidden = true;
            badgeEl.classList.remove('is-visible');
        });
    }

    /**
     * Enables standard WAI-ARIA arrow, Home, and End keyboard switching on a [role="tablist"].
     * Triggers .click() on the target tab so existing panel switching and state logic stay in sync.
     */
    function bindTablistA11y(tablistEl) {
        if (!tablistEl || tablistEl.dataset.gilosTablistBound === '1') return;
        tablistEl.dataset.gilosTablistBound = '1';

        tablistEl.addEventListener('keydown', function (e) {
            if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].indexOf(e.key) === -1) return;
            var tabs = Array.prototype.slice.call(tablistEl.querySelectorAll('[role="tab"]:not([disabled])')).filter(function (tab) {
                return !tab.hidden && tab.offsetParent !== null;
            });
            if (!tabs.length) return;
            var currentIndex = tabs.indexOf(document.activeElement);
            if (currentIndex === -1) {
                currentIndex = tabs.findIndex(function (tab) {
                    return tab.getAttribute('aria-selected') === 'true' || tab.classList.contains('active');
                });
                if (currentIndex === -1) currentIndex = 0;
            }

            var nextIndex = currentIndex;
            if (e.key === 'ArrowRight') nextIndex = (currentIndex + 1) % tabs.length;
            else if (e.key === 'ArrowLeft') nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
            else if (e.key === 'Home') nextIndex = 0;
            else if (e.key === 'End') nextIndex = tabs.length - 1;

            e.preventDefault();
            var targetTab = tabs[nextIndex];
            if (targetTab) {
                targetTab.focus();
                targetTab.click();
            }
        });
    }

    function resolveElement(target) {
        if (!target) return null;
        return typeof target === 'string' ? document.getElementById(target) : target;
    }

    function getOtpValue(containerOrId) {
        var container = resolveElement(containerOrId);
        if (!container) return '';
        return Array.from(container.querySelectorAll('.otp-input')).map(function (i) { return i.value || ''; }).join('');
    }

    function syncOtpFilledState(container) {
        if (!container) return;
        container.querySelectorAll('.otp-input').forEach(function (inp) {
            inp.classList.toggle('is-filled', Boolean(inp.value && inp.value.trim()));
        });
    }

    function clearOtpInputs(containerOrId, focusFirst) {
        var container = resolveElement(containerOrId);
        if (!container) return;
        var shouldFocus = focusFirst !== false;
        var inputs = container.querySelectorAll('.otp-input');
        inputs.forEach(function (inp) {
            inp.value = '';
            inp.classList.remove('error', 'is-filled');
        });
        if (container._otpOptions && typeof container._otpOptions.onChange === 'function') {
            container._otpOptions.onChange('');
        }
        if (shouldFocus && inputs.length) {
            inputs[0].focus();
        }
    }

    function shakeOtpContainer(containerOrId, markError) {
        var container = resolveElement(containerOrId);
        if (!container) return;
        var hasError = markError !== false;
        container.querySelectorAll('.otp-input').forEach(function (inp) {
            inp.classList.toggle('error', hasError);
        });
        container.classList.remove('is-shake');
        void container.offsetWidth;
        container.classList.add('is-shake');
    }

    function bindOtpInputs(containerOrId, options) {
        var container = resolveElement(containerOrId);
        if (!container) return;
        container._otpOptions = options || {};
        syncOtpFilledState(container);
        if (container.dataset.otpBound === '1') {
            if (typeof container._otpOptions.onChange === 'function') {
                container._otpOptions.onChange(getOtpValue(container));
            }
            return;
        }
        container.dataset.otpBound = '1';

        var inputs = container.querySelectorAll('.otp-input');
        var notify = function (triggerComplete) {
            syncOtpFilledState(container);
            var opts = container._otpOptions || {};
            var code = getOtpValue(container);
            if (typeof opts.onChange === 'function') opts.onChange(code);
            if (triggerComplete && code.length === inputs.length && typeof opts.onComplete === 'function') {
                opts.onComplete(code);
            }
        };
        var isLocked = function () {
            var opts = container._otpOptions || {};
            return typeof opts.isDisabled === 'function' && Boolean(opts.isDisabled());
        };

        inputs.forEach(function (input, idx) {
            input.addEventListener('input', function (e) {
                if (isLocked()) {
                    e.target.value = e.target.value.replace(/[^0-9]/g, '').slice(0, 1);
                    return;
                }
                var clean = e.target.value.replace(/[^0-9]/g, '');
                inputs.forEach(function (inp) { inp.classList.remove('error'); });
                if (clean.length > 1) {
                    var count = Math.min(clean.length, inputs.length - idx);
                    for (var i = 0; i < count; i++) {
                        inputs[idx + i].value = clean[i];
                    }
                    inputs[Math.min(idx + count, inputs.length - 1)].focus();
                } else {
                    e.target.value = clean;
                    if (clean && idx < inputs.length - 1) {
                        inputs[idx + 1].focus();
                    }
                }
                notify(true);
            });

            input.addEventListener('paste', function (e) {
                e.preventDefault();
                if (isLocked()) return;
                var clip = ((e.clipboardData || window.clipboardData).getData('text') || '')
                    .replace(/[^0-9]/g, '')
                    .slice(0, inputs.length);
                if (!clip) return;
                inputs.forEach(function (inp) { inp.classList.remove('error'); });
                for (var i = 0; i < inputs.length; i++) {
                    inputs[i].value = clip[i] || '';
                }
                if (inputs.length) {
                    inputs[Math.min(clip.length, inputs.length - 1)].focus();
                }
                notify(true);
            });

            input.addEventListener('keydown', function (e) {
                if (isLocked()) {
                    if (e.key !== 'Tab') e.preventDefault();
                    return;
                }
                if (e.key === 'Backspace' && !e.target.value && idx > 0) {
                    inputs.forEach(function (inp) { inp.classList.remove('error'); });
                    inputs[idx - 1].value = '';
                    inputs[idx - 1].focus();
                    notify(false);
                } else if (e.key === 'ArrowLeft' && idx > 0) {
                    e.preventDefault();
                    inputs[idx - 1].focus();
                } else if (e.key === 'ArrowRight' && idx < inputs.length - 1) {
                    e.preventDefault();
                    inputs[idx + 1].focus();
                } else if (e.key === 'Enter') {
                    var code = getOtpValue(container);
                    var opts = container._otpOptions || {};
                    if (code.length === inputs.length && typeof opts.onComplete === 'function') {
                        e.preventDefault();
                        opts.onComplete(code);
                    }
                }
            });
        });
    }

    window.GilosUI = {
        icon: icon,
        escapeHtml: escapeHtml,
        toast: toast,
        copyText: copyText,
        setButtonLoading: setButtonLoading,
        parseUserAgent: parseUserAgent,
        getDeviceIconSvg: getDeviceIconSvg,
        formatRelativeTime: formatRelativeTime,
        formatExactTime: formatExactTime,
        evaluatePassword: evaluatePassword,
        attachPasswordStrength: attachPasswordStrength,
        attachCapsLockWarning: attachCapsLockWarning,
        bindModalA11y: bindModalA11y,
        bindTablistA11y: bindTablistA11y,
        bindOtpInputs: bindOtpInputs,
        getOtpValue: getOtpValue,
        clearOtpInputs: clearOtpInputs,
        shakeOtpContainer: shakeOtpContainer
    };
})(window);

