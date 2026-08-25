module.exports = {
  stylesheet: [
    'https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap'
  ],
  css: `
    :root {
      --primary: #0F172A;
      --accent: #0284C7;
      --text-main: #334155;
      --border: #CBD5E1;
    }
    
    body {
      font-family: 'Roboto', sans-serif !important;
      color: var(--text-main);
      line-height: 1.6;
      font-size: 11pt;
      margin: 0;
      padding: 0;
    }

    .markdown-body {
      box-sizing: border-box;
      max-width: 100%;
      margin: 0 auto;
      padding: 0;
      font-family: inherit;
    }
    
    /* Cover Page Elements */
    .cover-page {
      height: 85vh;
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: flex-start;
      border-left: 4px solid var(--accent);
      padding-left: 30px;
      margin-left: 15px;
      margin-top: 50px;
    }
    
    .cover-subtitle {
      text-transform: uppercase;
      letter-spacing: 0.1em;
      font-size: 0.9em;
      font-weight: 700;
      color: var(--accent);
      margin-bottom: 0.5rem;
    }
    
    .cover-title {
      font-size: 3.8em;
      font-weight: 700;
      line-height: 1.1;
      margin: 0 0 0.1em 0;
      color: var(--primary);
      border: none !important;
      padding: 0 !important;
    }
    
    .cover-description {
      font-size: 1.3em;
      font-weight: 300;
      color: var(--text-main);
      max-width: 80%;
      margin-bottom: 4rem;
    }
    
    .cover-footer {
      font-size: 0.9em;
      color: #94A3B8;
      margin-top: auto;
      font-weight: 500;
    }
    
    .page-break { page-break-before: always; }

    /* Typography */
    h1, h2, h3, h4 {
      font-weight: 700;
      color: var(--primary);
      margin-top: 2em;
      margin-bottom: 0.75em;
    }
    
    h1 {
      font-size: 1.8em;
      border-bottom: 2px solid var(--border);
      padding-bottom: 0.3em;
    }
    
    h2 { font-size: 1.4em; }
    h3 { font-size: 1.15em; color: var(--accent); }
    
    p { margin-bottom: 1.2em; color: var(--text-main); font-weight: 400; text-align: justify; }
    
    /* Lists */
    ul, ol { padding-left: 1.5em; margin-bottom: 1.5em; }
    li { margin-bottom: 0.5em; text-align: justify; }
    li > strong { color: var(--primary); }

    /* Tables */
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 1.5em 0;
    }
    th, td {
      border: 1px solid var(--border);
      padding: 12px;
      text-align: left;
    }
    th {
      background-color: #F8FAFC;
      color: var(--primary);
      font-weight: 700;
    }
  `,
  pdf_options: {
    format: 'A4',
    margin: { top: '30mm', right: '30mm', bottom: '30mm', left: '30mm' },
    displayHeaderFooter: true,
    headerTemplate: '<span></span>',
    footerTemplate: '<div style="font-size: 9px; font-family: \'Roboto\', sans-serif; width: 100%; display: flex; justify-content: space-between; padding: 0 30mm; color: #94A3B8;"><span>PHANTOMGATE TECHNICAL REPORT</span><span class="pageNumber"></span></div>'
  }
};
