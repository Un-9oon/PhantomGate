from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode=True
import re, json, html, math, zipfile
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Flowable, KeepTogether
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from pypdf import PdfReader

ROOT=Path(__file__).resolve().parents[1]
ap=argparse.ArgumentParser(); ap.add_argument('--output-dir',default=str(ROOT/'outputs')); args=ap.parse_args()
OUT=Path(args.output_dir).resolve(); OUT.mkdir(parents=True,exist_ok=True)
DIAG=OUT/'diagrams'; DIAG.mkdir(exist_ok=True)
NAVY='#142D45'; BLUE='#176B91'; PALE='#EDF4F7'; GRAY='#52616D'; ORANGE='#A75228'
styles=getSampleStyleSheet()
styles.add(ParagraphStyle(name='BodyF',fontName='Times-Roman',fontSize=11.5,leading=16,alignment=TA_JUSTIFY,spaceAfter=9))
styles.add(ParagraphStyle(name='H1F',fontName='Helvetica-Bold',fontSize=19,leading=24,textColor=colors.HexColor(NAVY),spaceAfter=17))
styles.add(ParagraphStyle(name='H2F',fontName='Helvetica-Bold',fontSize=12,leading=16,textColor=colors.HexColor(BLUE),spaceBefore=9,spaceAfter=7))
styles.add(ParagraphStyle(name='SmallF',fontName='Helvetica',fontSize=8.5,leading=12,spaceAfter=7))
styles.add(ParagraphStyle(name='CellF',fontName='Helvetica',fontSize=8.3,leading=11))
styles.add(ParagraphStyle(name='CaptionF',fontName='Helvetica',fontSize=9,leading=12,textColor=colors.HexColor(GRAY),spaceBefore=7,spaceAfter=12))
styles.add(ParagraphStyle(name='CoverF',fontName='Helvetica-Bold',fontSize=34,leading=40,textColor=colors.HexColor(NAVY),spaceAfter=18))
styles.add(ParagraphStyle(name='SubF',fontName='Helvetica',fontSize=17,leading=24,textColor=colors.HexColor(BLUE),spaceAfter=18))
W=453
pages=[]; figs=[]; tabs=[]; md=[]
def para(t,sty='BodyF'): return Paragraph(t,styles[sty])
def table(headers,rows,widths=None):
    hs=ParagraphStyle('TableHeadF',parent=styles['CellF'],textColor=colors.white,fontName='Helvetica-Bold')
    data=[[Paragraph(html.escape(str(x)),hs) for x in headers]]+[[para(html.escape(str(x)),'CellF') for x in row] for row in rows]
    t=Table(data,colWidths=widths or [W/len(headers)]*len(headers),repeatRows=1,hAlign='LEFT')
    t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor(NAVY)),('TEXTCOLOR',(0,0),(-1,0),colors.white),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),7),('RIGHTPADDING',(0,0),(-1,-1),7),('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),7),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.HexColor(PALE),colors.white]),('LINEBELOW',(0,0),(-1,0),0.6,colors.HexColor(BLUE)),('LINEBELOW',(0,1),(-1,-1),0.3,colors.HexColor('#D7E0E5'))]))
    return t

ROUTES={
 'figure-4-2':{('s','l'):[(310,170),(345,170)],('l','s'):[(345,140),(310,140)],('r','s'):[(200,255),(200,195)],('s','r'):[(255,195),(255,255)]},
 'figure-4-3':{('p4','p2'):[(171,100),(140,100),(140,305),(171,305)]},
 'figure-4-7':{('e','c'):[(300,17),(316,17),(316,157),(300,157)]},
 'figure-4-11':{('ctrl','lab'):[(68,210),(68,233),(385,233),(385,210)]},
 'figure-4-12':{('valid','failed'):[(164,285),(148,285),(148,60),(164,60)]}
}

class Diagram(Flowable):
    def __init__(self,key,title,nodes,edges,h=310,notes=None):
        Flowable.__init__(self); self.width=W; self.height=h; self.key=key; self.nodes=nodes; self.edges=edges; self.title=title; self.notes=notes or []
        self.svg()
    def route(self,a,b,n):
        if (a,b) in ROUTES.get(self.key,{}): return ROUTES[self.key][(a,b)]
        x,y,xx,yy=self.points(n[a],n[b])
        if self.key=='figure-4-5':
            if n[a][-1]=='actor':x=n[a][1]+n[a][3]/2+(11 if xx>x else -11);y=n[a][2]+n[a][4]/2+2
            if n[b][-1]=='actor':xx=n[b][1]+n[b][3]/2+(-11 if x<xx else 11);yy=n[b][2]+n[b][4]/2+2
        return [(x,y),(xx,yy)]
    def label_point(self,pts):
        segments=list(zip(pts,pts[1:]));p,q=max(segments,key=lambda pq:(pq[0][0]-pq[1][0])**2+(pq[0][1]-pq[1][1])**2)
        return (p[0]+q[0])/2,(p[1]+q[1])/2
    def svg(self):
        h=self.height; n={x[0]:x for x in self.nodes}; s=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{h}" viewBox="0 0 {W} {h}"><rect width="100%" height="100%" fill="white"/><defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="{BLUE}"/></marker></defs>']
        if self.key=='figure-4-5': s.append(f'<rect x="120" y="{h-325}" width="214" height="325" fill="none" stroke="{GRAY}"/><text x="227" y="{h-332}" text-anchor="middle" font-family="Arial" font-size="8">PhantomGate-AI</text>')
        for a,b,label,*opt in self.edges:
            pts=self.route(a,b,n)
            s.append('<polyline points="'+' '.join(f'{x},{h-y}' for x,y in pts)+f'" fill="none" stroke="{BLUE}" stroke-width="1.1" marker-end="url(#arrow)"/>')
            if label:
                mx,my=self.label_point(pts);my=h-my;sw=max(22,len(label)*4.4)
                s.append(f'<rect x="{mx-sw/2}" y="{my-9}" width="{sw}" height="12" fill="white"/><text x="{mx}" y="{my}" text-anchor="middle" font-family="Arial" font-size="8" fill="{GRAY}">{html.escape(label)}</text>')
        for _,x,y,w,hh,label,*kind in self.nodes:
            k=kind[0] if kind else 'box'
            if self.key=='figure-4-5' and k=='actor':
                cx=x+w/2; cy=h-(y+hh/2)
                s.append(f'<circle cx="{cx}" cy="{cy-12}" r="5" fill="white" stroke="{BLUE}"/><path d="M {cx} {cy-7} V {cy+7} M {cx-10} {cy-2} H {cx+10} M {cx} {cy+7} L {cx-9} {cy+17} M {cx} {cy+7} L {cx+9} {cy+17}" fill="none" stroke="{BLUE}"/><text x="{cx}" y="{cy+29}" text-anchor="middle" font-family="Arial" font-size="8">{html.escape(label)}</text>');continue
            fill=PALE if k!='actor' else '#FFF5ED'; rx=hh/2 if k=='process' else 4
            s.append(f'<rect x="{x}" y="{h-y-hh}" width="{w}" height="{hh}" rx="{rx}" fill="{fill}" stroke="{BLUE}"/>')
            lines=label.split('\n'); yy=h-(y+hh/2)+(len(lines)-1)*-5.7
            for i,line in enumerate(lines): s.append(f'<text x="{x+w/2}" y="{yy+i*11.4+3}" text-anchor="middle" font-family="Arial" font-size="8.4" fill="{NAVY}">{html.escape(line)}</text>')
            if k=='store': s.append(f'<line x1="{x+7}" y1="{h-y}" x2="{x+7}" y2="{h-y-hh}" stroke="{BLUE}"/>')
        for x,y,t in self.notes:s.append(f'<text x="{x}" y="{h-y}" font-family="Arial" font-size="8" fill="{GRAY}">{html.escape(t)}</text>')
        if self.key=='figure-4-5':
            import re as _re
            s=[_re.sub(r' marker-end="url\(#arrow\)"','',v) for v in s]
        s.append('</svg>'); (DIAG/(self.key+'.svg')).write_text('\n'.join(s),encoding='utf-8')
    def points(self,p,q):
        _,x,y,w,h,*_=p; _,xx,yy,ww,hh,*_=q; cx,cy=x+w/2,y+h/2; dx,dy=xx+ww/2-cx,yy+hh/2-cy
        if abs(dx)/(w or 1)>abs(dy)/(h or 1):return (x+w if dx>0 else x,cy,xx if dx>0 else xx+ww,yy+hh/2)
        return (cx,y+h if dy>0 else y,xx+ww/2,yy if dy>0 else yy+hh)
    def draw(self):
        c=self.canv; n={x[0]:x for x in self.nodes}
        if self.key=='figure-4-5':
            c.setStrokeColor(colors.HexColor(GRAY));c.rect(120,0,214,325,fill=0,stroke=1);c.setFont('Helvetica',8);c.drawCentredString(227,332,'PhantomGate-AI')
        for a,b,label,*opt in self.edges:
            pts=self.route(a,b,n);c.setStrokeColor(colors.HexColor(BLUE));c.setLineWidth(1)
            for (x1,y1),(x2,y2) in zip(pts,pts[1:]):c.line(x1,y1,x2,y2)
            (x1,y1),(x2,y2)=pts[-2:]
            angle=math.atan2(y2-y1,x2-x1); path=c.beginPath();path.moveTo(x2,y2);path.lineTo(x2-6*math.cos(angle-.45),y2-6*math.sin(angle-.45));path.lineTo(x2-6*math.cos(angle+.45),y2-6*math.sin(angle+.45));path.close();c.setFillColor(colors.HexColor(BLUE))
            if self.key!='figure-4-5':c.drawPath(path,fill=1,stroke=0)
            if label:
                c.setFont('Helvetica',7.5);tw=c.stringWidth(label,'Helvetica',7.5);mx,my=self.label_point(pts);c.setFillColor(colors.white);c.rect(mx-tw/2-3,my-2,tw+6,11,fill=1,stroke=0);c.setFillColor(colors.HexColor(GRAY));c.drawCentredString(mx,my+1,label)
        for _,x,y,w,h,label,*kind in self.nodes:
            k=kind[0] if kind else 'box'
            if self.key=='figure-4-5' and k=='actor':
                cx=x+w/2;cy=y+h/2;c.setStrokeColor(colors.HexColor(BLUE));c.circle(cx,cy+12,5,fill=0);c.line(cx,cy+7,cx,cy-7);c.line(cx-10,cy+2,cx+10,cy+2);c.line(cx,cy-7,cx-9,cy-17);c.line(cx,cy-7,cx+9,cy-17);c.setFillColor(colors.HexColor(NAVY));c.setFont('Helvetica',8);c.drawCentredString(cx,cy-29,label);continue
            c.setStrokeColor(colors.HexColor(BLUE));c.setFillColor(colors.HexColor('#FFF5ED' if k=='actor' else PALE));c.roundRect(x,y,w,h,h/2 if k=='process' else 4,fill=1,stroke=1)
            if k=='store':c.line(x+7,y,x+7,y+h)
            lines=label.split('\n');c.setFillColor(colors.HexColor(NAVY));c.setFont('Helvetica',8.4)
            for i,line in enumerate(lines): c.drawCentredString(x+w/2,y+h/2+(len(lines)-1)*5.7-i*11.4-3,line)
        c.setFont('Helvetica',8);c.setFillColor(colors.HexColor(GRAY))
        for x,y,t in self.notes:c.drawString(x,y,t)

def P(title,*blocks):
    pages.append((title,list(blocks)));return len(pages)
def H(t):return ('h',t)
def T(title,headers,rows,widths=None):return ('t',title,headers,rows,widths)
def F(num,title,nodes,edges,h=310,notes=None):return ('f',num,title,nodes,edges,h,notes)
def B(*items):return ('b',items)


ROUTES.update({'figure-4-3': {('px','lab'):[(281,360),(343,360)],('lab','px'):[(343,340),(281,340)],('san','exp'):[(171,255),(147,255),(147,65),(171,65)]}, 'figure-4-7':{('e','c'):[(300,17),(316,17),(316,157),(300,157)]},'figure-4-11':{('px','lab'):[(68,210),(68,232),(385,232),(385,210)]},'figure-4-4':{('rej','out'):[(62,170),(62,30),(390,30),(390,65)]}})
P('Title page',('cover',))
P('Declaration and document status',
 'This final-year-project design report defines the current agreed scope of PhantomGate-AI: retain the existing reverse proxy as the main system and embed a separately trained assistant for evidence-grounded authentication-outcome and technical-failure diagnosis in controlled laboratories. It supersedes the earlier action-selection-agent report.',
 H('Declaration and attribution'),
 'The original PhantomGate framework is an existing software foundation, not a new student invention. Students must identify reused code, their own instrumentation, dataset, trained model, reliability changes, evaluation, and writing assistance according to institutional policy. This draft is unsigned and does not assert approval or authorship by any named person.',
 T('Administrative details',['Field','Submission status'],[['Student names / registration IDs','Not supplied'],['University / department / degree','Not supplied'],['Supervisor / academic session','Not supplied'],['Declaration and approval signatures','Pending; obtain actual signatures'],['Revision / prepared','3.0 / 22 October 2026'],['Implementation and experiment status','Proposed; no trained-model results claimed']],[170,283]),
 H('Formatting and intended use'),
 'A conventional A4 FYP format is used because no institution template was supplied. Replace the cover and approval wording with the institution requirements. Add genuine acknowledgements before submission. The implementation handover chapter and companion PROJECT_SPEC.json are designed to make the scope understandable without reading this conversation.')
P('Abstract',
 'PhantomGate-AI proposes an AI-assisted reverse-proxy framework for controlled authentication-security assessments. The existing Go reverse proxy remains the primary traffic-processing system. A non-blocking observation pipeline supplies sanitized event sequences to a student-trained diagnostic model. The assistant estimates authentication-flow outcomes and associated technical-failure categories, identifies insufficient evidence, and returns evidence-linked explanations for an operator. It does not control routing, generate payloads, select targets, or modify assessment authorization.',
 'The research problem is the interpretation of incomplete and ambiguous laboratory observations: a failed interaction may reflect application rejection, proxy failure, upstream unavailability, client interruption, or insufficient telemetry. The proposed approach separates model predictions from ground truth obtained through independently instrumented synthetic applications and verified fault injections. Outcome and failure labels are modeled separately because an incomplete flow and a technical failure can coexist.',
 'The evaluation compares explicit rules, logistic regression, gradient-boosted trees, and an optional small sequence model using application- and scenario-group holdouts. Measurements include per-class precision and recall, macro-F1, selective prediction risk, calibration, missing-event sensitivity, and added resource overhead. Conventional engineering work addresses timeouts, cancellation, storage durability, immutable snapshots, bounded queues, and shutdown. Expected deliverables are an enhanced reverse proxy, a trained assistant, a labeled laboratory benchmark, reproducible evaluations, and an implementation handover package. Novelty and robustness remain claims to validate, not established achievements.',
 H('Keywords'),
 'Reverse proxy; penetration-testing laboratory; authentication assessment; supervised learning; failure diagnosis; sanitized telemetry; uncertainty; cross-application evaluation.',
 H('One-sentence project identity'),
 'Keep PhantomGate as the reverse proxy; add a trained, read-only assistant that explains observed assessment outcomes using sanitized telemetry and independent verification.')
P('Table of contents',('toc',))
P('List of figures, tables and abbreviations',('lists',))

P('1. Introduction and project identity',
 H('1.1 Background'),
 'A reverse proxy handles requests and responses between a browser and an upstream web application. In this project it is used inside an authorized laboratory to observe synthetic authentication workflows. An endpoint payload is not a prerequisite for the proposed reverse-proxy experiment. The research assistant analyzes observations; the reverse proxy remains the product being enhanced.',
 H('1.2 Problem statement'),
 'A failed authentication experiment does not by itself establish a security result. Application rejection, upstream faults, local proxy errors, interrupted clients, and missing events can produce superficially similar traces. Incorrect interpretation can lead to unsupported assessment conclusions. A single HTTP status code is insufficient to establish authenticated state or the root cause of a failure.',
 H('1.3 Aim'),
 'Enhance PhantomGate with a student-trained diagnostic assistant and measured reliability improvements, while keeping its reverse-proxy architecture central and independently verifying the assistant\'s conclusions in a controlled laboratory.',
 H('1.4 Research question'),
 'Can a model trained on sanitized reverse-proxy telemetry distinguish authentication outcomes and technical-failure categories on unseen laboratory applications more accurately than rule-based analysis, while keeping overhead bounded?',
 H('1.5 Scope decision'),
 'The earlier proposal for an autonomous next-action policy is superseded. This report specifies outcome and failure diagnosis. Automated payload delivery, exploit selection, phishing optimization, autonomous traffic rewriting, and universal MFA-bypass claims are outside the implementation scope.')
P('1. Objectives and proposed solution',
 T('Table 1.1 - Objectives and deliverables',['ID','Objective','Evidence / deliverable'],[['O1','Retain and instrument the Go reverse proxy','Metadata events without inference in the forwarding path'],['O2','Train an embedded diagnostic assistant','Versioned dataset, labels, model and training configuration'],['O3','Validate outcomes independently','App-oracle and verified fault-injection records'],['O4','Evaluate generalization and usefulness','Rules and ML comparisons on held-out apps'],['O5','Improve measured reliability','Load, failure, recovery and cancellation test records'],['O6','Enable implementation handover','Code map, contracts, milestones and acceptance tests']],[35,205,213]),
 H('1.6 Proposed solution'),
 'Collect allowlisted metadata from the proxy; assign pseudonymous correlation IDs; build bounded per-flow windows; classify outcomes and failures; abstain on insufficient evidence; and display structured diagnoses with references to observed events. Compare predictions with the independent oracle only in the evaluation pipeline.',
 H('1.7 Meaning of accuracy and robustness'),
 'Accuracy refers to correct diagnostic predictions and supported conclusions. Robustness refers to reliable system behavior under load, missing data, dependency failures, and interruption. AI is not a substitute for timeouts, durable storage, concurrency ownership, or correct network handling.',
 H('1.8 Academic balance'),
 'The Penetration Testing contribution is a scoped authentication assessment workflow, evidence verification, reporting and remediation retests. The AI contribution is dataset design, student-run training, model comparison, uncertainty evaluation and generalization analysis.')

P('2. Literature review - method and prior systems',
 H('2.1 Review method and limitations'),
 'This focused narrative review uses primary publication pages, author manuscripts, research records, standards, and the baseline repository. Sources were checked on 22 October 2026. Queries covered automated penetration testing, reverse-proxy authentication assessment, log anomaly detection, and failure diagnosis. This is not an exhaustive systematic review and does not establish that the proposed combination is globally unique.',
 H('2.2 AI-assisted penetration testing'),
 'PentestGPT [1] evaluates LLM-assisted penetration testing and addresses loss of assessment context through interacting modules. Its contribution establishes that AI-guided assessment is prior work. AutoPentester [2] studies iterative tool-driven automation and reports benchmark comparisons. Adding an assistant to a security tool therefore cannot itself be claimed as novel.',
 H('2.3 Reverse-proxy phishing analysis'),
 'Catching Transparent Phish [3] analyzes MITM phishing toolkits and develops network-based detection. It provides context for the existing framework but asks a different question from diagnosing the reliability and outcome of a controlled experiment. Its reported detector performance must not be transferred to this proposed model.',
 H('2.4 Authentication semantics'),
 'Ulqinaku et al. [4] study social-engineering downgrade from FIDO to alternative authentication methods. WebAuthn [8] specifies relying-party and origin validation. These sources do not support blanket claims that a reverse proxy defeats all MFA. The lab must distinguish protocol behavior, fallback policy, and infrastructure malfunction.')
P('2. Literature review - diagnosis and candidate gap',
 H('2.5 Log-based learning is established'),
 'LogBERT [5] learns normal log-sequence patterns using self-supervised training and detects deviations. This establishes sequence-based log anomaly detection as prior work. An anomaly score does not automatically identify a specific authentication outcome or establish the cause of a failure.',
 'LogRCA [6] studies root-cause candidate identification in distributed-service logs using semi-supervised learning and expert-labeled failures. Its existence means that AI-based failure diagnosis itself is not new. PhantomGate-AI must compare its task definition and evidence requirements with such work rather than comparing only with penetration-testing agents.',
 H('2.6 Candidate research gap'),
 'The reviewed systems emphasize general assessment automation, phishing-toolkit detection, or general service-log diagnosis. This proposal investigates a narrower task: jointly label authentication outcomes and technical-failure categories from secret-free proxy observations, with an independent lab oracle, explicit abstention, and held-out application evaluation.',
 'That positioning is an inference from the reviewed sources, not a proven absence of related work. A follow-up review should search authentication-specific diagnosis, proxy observability, process mining, and uncertainty-aware log analysis before any first-of-its-kind claim.',
 H('2.7 Falsifiable contribution'),
 'A successful study would show useful diagnosis beyond well-designed rules under stated conditions. If known error flags already solve the task, or a heuristic matches the model on unseen apps, report that result. The contribution may then be a benchmark, replication, or negative-result study rather than a superior AI algorithm.')
P('2. Related-work comparison and novelty boundaries',
 T('Table 2.1 - Research comparison',['Source','Established scope','Proposed distinction to evaluate'],[['[1] PentestGPT, 2024','LLM assessment assistance and context','Proxy-specific outcome/failure labels'],['[2] AutoPentester, 2025','Iterative pentesting automation','Read-only diagnosis rather than action planning'],['[3] Transparent Phish, 2021','MITM toolkit analysis and detection','Diagnosis of lab experiment observations'],['[4] FIDO downgrade, 2021','User behavior and fallback attacks','Separate rejection from technical faults'],['[5] LogBERT, 2021','Log-sequence anomaly detection','Task-specific labels and independent oracle'],['[6] LogRCA, 2024','Distributed-service failure diagnosis','Authentication context; missing events; holdouts']],[114,157,182]),
 H('2.8 What can be original'),
 'Potential student contributions are a documented authentication-trace benchmark, a reproducible oracle-alignment method, a calibrated diagnostic model, and an integrated proxy assistant evaluated under application shift. Each contribution needs comparison with relevant existing work; a new project name or code integration is not sufficient.',
 H('2.9 What is not claimed'),
 'Reverse-proxy interception, generic AI assistants, log anomaly detection, root-cause analysis, and unseen-environment testing already have substantial prior work. The proposed model does not prove causation from correlations alone. Production certification and universal superiority are not claimed.')

P('3. Requirements and scope',
 H('3.1 Actors and operating assumptions'),
 'A student operator starts scoped laboratory runs. A supervisor approves scope. A researcher curates labels and trains models. An examiner reviews repeatability and evidence. All applications and identities are synthetic and provisioned within an isolated lab; default external egress is denied.',
 T('Table 3.1 - Functional requirements',['ID','Requirement','Verification'],[['FR01','Validate a frozen lab manifest before start','Reject unauthorized target or invalid manifest'],['FR02','Emit allowlisted proxy metadata events','Schema and redaction tests'],['FR03','Construct bounded correlated flow windows','Window, concurrency and missing-event fixtures'],['FR04','Predict outcome and failure with confidence','Offline fixtures and model-contract tests'],['FR05','Abstain when evidence is inadequate','Incomplete-window and schema-error tests'],['FR06','Keep oracle labels separate from inference','Split and feature-allowlist audit'],['FR07','Display evidence-linked diagnoses and reports','Every explanation references existing events'],['FR08','Support disable, cancellation and cleanup','Model outage and shutdown tests']],[42,246,165]),
 H('3.2 Assistant authority'),
 'The assistant may summarize observed evidence, return diagnostic categories, identify missing observations, and suggest a repeat of an approved lab check for human review. It may not choose external targets, invoke shell commands, change routing, generate payloads, or declare a verified security finding without independent evidence.')
P('3. Quality requirements and acceptance targets',
 T('Table 3.2 - Proposed quality targets',['ID','Requirement / initial target','Acceptance evidence'],[['NFR01','No AI-dependent wait in request forwarding','Request path remains responsive during model outage'],['NFR02','No secret values in exported model data','Canary scans and allowlist schema checks'],['NFR03','Memory and queue capacity are bounded','Saturation test and observable drop counts'],['NFR04','No detected data races in supported paths','Concurrent tests and Go race-check logs'],['NFR05','Committed diagnosis records survive interruption','Crash-recovery tests'],['NFR06','Local p95 diagnosis <= 250 ms after window closure','Measured on disclosed hardware'],['NFR07','Proxy p95 overhead <= 10% at a declared load','Paired AI-off/on test with confidence interval'],['NFR08','No new work after cancellation; cleanup <= 10 s','Cancellation and worker-drain tests']],[43,237,173]),
 'These are provisional engineering acceptance targets, not achieved results. Freeze final thresholds after a pilot and before final evaluation. Specify the workload, network conditions, event rates and supported platform. An absolute latency limit should accompany relative overhead if the baseline is very fast.',
 H('3.3 Requirements traceability'),
 'O1 maps to FR01-FR03 and NFR01-NFR03; O2 maps to FR04-FR05; O3 maps to FR06-FR07; O4 maps to the held-out protocol; O5 maps to NFR04-NFR08; O6 maps to the handover chapter and acceptance matrix. AI failure reduces diagnostic availability, not forwarding availability.')

P('4. System architecture',
 F('4.1','Reverse proxy with an observational AI assistant',[
 ('br',0,275,125,45,'Synthetic browser','actor'),('px',164,275,125,45,'Go reverse proxy\nPrimary data path'),('app',328,275,125,45,'Synthetic lab app','actor'),
 ('san',164,165,125,50,'Metadata sanitizer\nAllowlist before queue'),('win',0,65,125,55,'Bounded queue +\nflow window builder'),('ai',164,65,125,55,'Local trained model\nOutcome + failure heads'),('db',328,65,125,55,'Diagnosis store\nEvidence references','store'),('ui',328,0,125,35,'Operator assistant view')],
 [('br','px','lab requests'),('px','app','forward'),('px','san','metadata only'),('san','win','non-blocking emit'),('win','ai','closed window'),('ai','db','prediction'),('db','ui','read diagnosis')],h=340),
 H('4.1 Data path versus assistant path'),
 'Browser-to-application forwarding is the primary path. Sanitized event emission uses a non-blocking bounded queue. A separate worker calls the model after a window closes. The request handler never waits for model inference. Full queues increment drop counters and mark affected windows incomplete.',
 H('4.2 Independent truth boundary'),
 'The oracle is deliberately absent from the live inference path. It is joined with frozen predictions only in the research evaluator. The model cannot read application ground-truth logs, injected-fault identifiers, scenario labels, or future events.')
P('4. Context data-flow diagram',
 F('4.2','Context DFD: lab traffic and diagnostic artifacts',[
 ('o',0,135,110,50,'Operator / supervisor','actor'),('s',145,120,165,75,'0. PhantomGate-AI\nReverse proxy + assistant','process'),('l',345,135,108,50,'Lab browser / app','actor'),('r',145,255,165,45,'Researcher / model curator','actor'),('e',145,10,165,45,'Examiner / evaluator','actor')],
 [('o','s','scope + run'),('s','l','proxied response'),('l','s','lab traffic'),('r','s','trained model'),('s','r','redacted dataset'),('s','e','predictions + report')],h=320),
 H('4.3 DFD notation and balancing'),
 'This report uses process 0 for the context diagram; Level 1 contains processes 1.0-5.0; Level 2 decomposes diagnostic process 4.0. Processes use rounded shapes, entities use tinted rectangles, and stores use marked rectangles. Arrows represent data flows, not scheduling.',
 'The lab entity aggregates the browser and application for context readability. The operator supplies frozen scope and run parameters. The researcher supplies a compatible model and receives redacted exports. The evaluator compares predictions with a separately provisioned oracle.')
P('4. DFD Level 1',
 F('4.3','Level 1: forwarding, observation, diagnosis and export',[
 ('o',0,410,110,35,'Operator','actor'),('p1',0,330,110,50,'1.0 Validate lab\nand initialize run','process'),('d1',0,230,110,48,'D1 Scope manifest\nRun configuration','store'),('r',343,230,110,45,'Researcher','actor'),('px',171,330,110,50,'2.0 Forward lab traffic','process'),('lab',343,330,110,50,'Lab browser / app','actor'),('san',171,230,110,50,'3.0 Sanitize events\nand build windows','process'),('ai',171,130,110,50,'4.0 Diagnose window','process'),('model',343,130,110,50,'D2 Model registry','store'),('exp',171,40,110,50,'5.0 Store and export\nreport / dataset','process'),('d3',343,40,110,50,'D3 Evidence store','store'),('out',0,40,110,50,'Examiner / researcher','actor')],
 [('o','p1','scope + start'),('p1','d1','frozen manifest'),('p1','px','run context'),('d1','px','constraints'),('px','lab','proxied traffic'),('lab','px','responses'),('px','san','metadata'),('san','ai','window'),('r','model','trained model'),('model','ai','pinned model'),('ai','exp','diagnosis'),('san','exp','redacted events'),('exp','d3','records'),('exp','out','report / data')],h=455),
 H('4.4 Boundary flows'),
 'Process 5.0 writes D3 and exports reports to the examiner and redacted data to the researcher. These preserve the context flows. The model is frozen during a run; oracle labels never feed live inference.')
P('4. DFD Level 2',
 F('4.4','Level 2: diagnostic process 4.0',[
 ('input',0,275,125,45,'From 3.0\nSanitized flow window','actor'),('a',164,275,125,45,'4.1 Validate schema\nand completeness','process'),('reg',328,275,125,45,'D2 Model registry','store'),('b',164,170,125,50,'4.2 Extract features\nand classify','process'),('c',164,65,125,50,'4.3 Calibrate and\napply abstention','process'),('out',328,65,125,50,'To 5.0\nDiagnosis record','actor'),('rej',0,170,125,50,'Unavailable / invalid\nExplicit status','actor')],
 [('input','a','window'),('a','b','valid features'),('reg','b','pinned model'),('a','rej','invalid / missing'),('b','c','class probabilities'),('c','out','prediction or abstain'),('rej','out','no prediction')],h=340),
 H('4.5 Inference boundary'),
 'The diagnosis record includes predicted outcome, predicted failure category, confidence, abstention reason, model version and evidence IDs. It is not an independent verifier verdict. A model outage or schema mismatch produces UNAVAILABLE or INVALID_INPUT without changing traffic forwarding.',
 'Missing telemetry is recorded separately from semantic flow outcome. A partial observation must not be labeled as an application rejection simply because no success event was seen.')
P('4. Use-case diagram and specifications',
 F('4.5','Use cases for the embedded assistant',[
 ('op',0,140,95,50,'Lab operator','actor'),('su',0,260,95,45,'Supervisor','actor'),('re',358,140,95,50,'Researcher','actor'),('ex',358,20,95,45,'Examiner','actor'),('u1',142,260,167,45,'UC01 Approve scoped run','process'),('u2',142,180,167,45,'UC02 Observe proxy run','process'),('u3',142,100,167,45,'UC03 Review diagnosis','process'),('u4',142,20,167,45,'UC04 Train and evaluate','process')],
 [('su','u1',''),('op','u2',''),('op','u3',''),('re','u4',''),('u3','ex',''),('u4','ex','')],h=350),
 T('Table 4.1 - Use-case outcomes',['Case','Preconditions','Success / alternative'],[['UC01','Lab owner approval and manifest','Approved frozen scope / reject'],['UC02','Healthy reset lab and approved scope','Traffic + observations / safe cancellation'],['UC03','Diagnosis and event references','Human-reviewed assessment / insufficient evidence'],['UC04','Frozen data and split manifest','Versioned model and metrics / invalid dataset']],[44,196,213]),
 'UC03 shows predictions and verified evaluation labels distinctly. A diagnosis may be wrong; the interface must not call it a confirmed vulnerability automatically.')
P('4. Misuse-case diagram',
 F('4.6','Misuse cases and controls',[
 ('bad',0,150,100,60,'Untrusted input /\nmisconfiguration','actor'),('m1',137,265,150,43,'MC01 Expand target scope','process'),('m2',137,180,150,43,'MC02 Export secrets','process'),('m3',137,95,150,43,'MC03 Present guess as proof','process'),('m4',137,10,150,43,'MC04 Block proxy via AI','process'),('c1',330,265,123,43,'Manifest + isolation'),('c2',330,180,123,43,'Allowlist + canaries'),('c3',330,95,123,43,'Oracle + evidence IDs'),('c4',330,10,123,43,'Bounded async worker')],
 [('bad','m1','attempt'),('bad','m2','attempt'),('bad','m3','attempt'),('bad','m4','attempt'),('m1','c1','mitigated by'),('m2','c2','mitigated by'),('m3','c3','mitigated by'),('m4','c4','mitigated by')],h=325),
 H('4.6 Testable misuse behavior'),
 'Reject an out-of-scope lab configuration before forwarding starts. Drop unapproved telemetry fields before enqueueing. Reject forged evidence references at report generation. Saturating or stopping the model service must not block the request handler.',
 'The diagnosis interface accepts structured data, not executable instructions. If a future natural-language renderer is added, untrusted event content must remain data and its prose may not override the recorded labels or authorization.')
P('4. Activity and lifecycle design',
 F('4.7','Observed flow and asynchronous diagnosis activity',[
 ('a',150,280,150,35,'Validate scoped run'),('b',150,210,150,35,'Forward lab interaction'),('c',150,140,150,35,'Emit sanitized events'),('d',150,70,150,35,'Close bounded window'),('e',150,0,150,35,'Diagnose and persist'),('stop',0,140,110,35,'Queue full: mark loss'),('done',343,0,110,35,'Operator review')],
 [('a','b','ready'),('b','c','metadata'),('c','d','queued'),('c','stop','saturated'),('d','e','terminal / idle'),('e','done','evidence-linked'),('e','c','next window')],h=325),
 H('4.7 Window closure'),
 'Close a flow window on an observed terminal event, an idle timeout, cancellation, maximum event count, or maximum duration. Record the closure reason. Observation windows bound memory and inference input; they are not themselves proof that the application authenticated or rejected the synthetic user.',
 H('4.8 Evidence ordering'),
 'Use monotonic duration measurement within a process and sequence numbers per flow. Treat cross-process timestamps as approximate. Correlation identifiers are generated by the lab controller and validated as opaque identifiers; do not derive them from passwords or cookie values.')
P('4. Sequence diagram',('sequence',),
 H('4.9 Runtime interaction'),
 'The proxy forwards the request independently of the diagnostic worker. Allowlisted metadata is emitted without waiting for inference. The worker submits a closed window to the local model and stores the returned diagnosis. The operator sees its confidence and status.',
 'Separately, the research evaluator joins frozen predictions to oracle records. The live model cannot query that oracle. If the model is unavailable, the worker records UNAVAILABLE and uses bounded retry or skips according to configuration; it never silently claims a successful diagnosis.')
P('4. Domain class model',
 F('4.9','Conceptual domain classes',[
 ('run',0,235,137,80,'RunContext\nrunId, scopeHash, modelId\nstart(), cancel(), close()'),('px',158,235,137,80,'PhantomProxy\nrequest handler\nServeHTTP(), emitMetadata()'),('sink',316,235,137,80,'EventSink\ncapacity, dropCount\nTryEmit(event)'),('window',0,100,137,80,'FlowWindow\nflowId, eventIds, closure\nappend(), close()'),('ai',158,100,137,80,'DiagnosisClient\nmodelVersion, schema\nPredict(window)'),('diag',316,100,137,80,'Diagnosis\noutcome, failure, status\nconfidence, evidenceIds'),('eval',158,0,137,55,'ResearchEvaluator\njoinOracle(), score()')],
 [('run','px','owns context'),('px','sink','non-blocking'),('sink','window','groups events'),('window','ai','input'),('ai','diag','returns'),('eval','diag','scores offline')],h=330),
 H('4.10 Implementation meaning'),
 'Existing PhantomProxy is retained; other types are proposed. EventSink has non-blocking semantics. DiagnosisClient owns model communication, deadlines and schema compatibility. ResearchEvaluator is excluded from runtime inference dependencies.',
 'The conceptual model is not a claim that these Go types already exist. The handover chapter maps responsibilities to existing files and proposed modules.')
P('4. Entity relationship diagram',
 F('4.10','Diagnostic evidence and research-label schema',[
 ('run',0,245,136,72,'Run\nPK run_id\nscope_hash, FK model_id'),('flow',158,245,136,72,'Flow\nPK flow_id; FK run_id\nclosure, completeness'),('model',316,245,137,72,'ModelVersion\nPK model_id\nartifact_hash, schema'),('event',0,105,136,82,'Event\nPK event_id; FK flow_id\nseq, kind, timing\nallowlisted metadata'),('diag',158,105,136,82,'Diagnosis\nPK diagnosis_id\nFK flow_id, model_id\nlabels, status, confidence'),('oracle',316,105,137,82,'OracleLabel [research]\nPK label_id; FK flow_id\ntruth labels, provenance'),('link',158,0,137,60,'DiagnosisEvidence\nPK/FK diagnosis_id\nPK/FK event_id')],
 [('run','flow','1 : many'),('model','diag','1 : many'),('flow','event','1 : many'),('flow','diag','1 : many'),('flow','oracle','1 : 0..many'),('diag','link','1 : many'),('event','link','1 : many')],h=335),
 H('4.11 Separation and integrity'),
 'OracleLabel is stored in a research-only database or access boundary. A runtime prediction may not query it. Foreign keys protect evidence references. One model may produce many diagnoses; multiple models may score the same frozen flow in offline comparison.',
 'Store no credential or session-token values in Event. Raw network bodies are not required for the proposed model. Persist versioned labels with provenance and reviewer status so corrections remain auditable.')
P('4. Deployment diagram',
 F('4.11','Isolated lab deployment with a local inference service',[
 ('host',0,260,453,55,'Research workstation\nOperator interface + separate training/evaluation environment'),('px',0,135,136,75,'Go proxy process\nSanitizer + queue\nWindow worker'),('ai',158,135,136,75,'Local Python service\nRead-only model\nNo target-network route'),('lab',316,135,137,75,'Isolated lab network\nSynthetic apps A/B/C\nSynthetic browser'),('db',0,10,136,65,'Evidence store\nRedacted events\nDiagnoses + audit'),('oracle',316,10,137,65,'Research-only oracle\nApp truth + verified\nfault-injection record')],
 [('host','px','approved run'),('host','ai','pinned model'),('px','ai','sanitized windows'),('px','lab','lab traffic'),('px','db','durable records'),('lab','oracle','truth records')],h=330),
 H('4.12 Deployment choices'),
 'A local sidecar is an embedded product component even though it is a separate process. It avoids coupling Go forwarding to Python inference. Bind the model service to loopback or an isolated service network, authenticate local calls where appropriate, and deny its target access.',
 'The offline evaluator may read both stores after predictions are frozen. The proxy and model receive no oracle credentials. Record actual OS support; the existing repository\'s cross-platform claims require verification.')
P('4. Run-state machine',
 F('4.12','Persistent run lifecycle',[
 ('new',0,265,125,40,'CREATED'),('valid',164,265,125,40,'VALIDATED'),('ready',328,265,125,40,'READY'),('running',328,150,125,45,'RUNNING'),('stopping',164,150,125,45,'DRAINING'),('closed',0,150,125,45,'CLOSED'),('failed',164,30,125,60,'FAILED_REQUIRES\n_REVIEW')],
 [('new','valid','scope valid'),('valid','ready','lab ready'),('ready','running','start'),('running','stopping','stop / fault / end'),('stopping','closed','cleanup complete'),('stopping','failed','cleanup failure'),('valid','failed','setup failure')],h=330),
 H('4.13 Degradation and restart'),
 'Assistant health is a separate dimension: HEALTHY, DEGRADED or UNAVAILABLE. A model outage need not end an otherwise authorized lab run. Show the diagnostic outage explicitly. Never translate missing predictions into NORMAL results.',
 'After a crash, mark interrupted runs for review, recover committed records, and verify lab cleanup before any new run. DRAINING stops new work, cancels or bounds outstanding requests, and flushes accepted events within a documented deadline.')

P('5. AI methodology - labels and ground truth',
 H('5.1 Two prediction heads'),
 'Use separate supervised targets: authentication outcome and technical-failure category. This avoids forcing mutually compatible conditions into one class. For example, an interrupted upstream connection can coexist with an incomplete authentication flow.',
 T('Table 5.1 - Version 1 label taxonomy',['Head','Values','Label authority'],[['Outcome','COMPLETE, REJECTED, INCOMPLETE, UNKNOWN','Instrumented app state and complete episode evidence'],['Failure','NONE, PROXY, UPSTREAM, CLIENT, UNKNOWN','Verified fault condition plus observed provenance'],['Prediction status','PREDICTED, ABSTAINED, UNAVAILABLE, INVALID_INPUT','Runtime evidence/schema/health checks']],[80,207,166]),
 'COMPLETE means the synthetic application confirms completion of its configured authentication flow. REJECTED means an explicit app-level rejection is confirmed. Neither implies that a vulnerability exists. UNKNOWN is a ground-truth ambiguity label; ABSTAINED is a model decision not to assert a label.',
 H('5.2 Oracle construction'),
 'The lab app records outcome events independently of the proxy. Fault injections occur only in lab fixtures and are verified as active; scheduling an injection is not sufficient evidence that it caused the observed failure. Multi-fault episodes receive a documented primary label or remain UNKNOWN and are reported separately.',
 'The oracle, fault ID, scenario name, hidden label and future events are forbidden as model features. Ground truth is joined only after inference or for supervised training targets.')
P('5. Dataset and feature engineering',
 T('Table 5.2 - Allowlisted input design',['Group','Examples','Restrictions'],[['Correlation','Opaque flow ID; sequence number','IDs used for grouping only, not model predictors'],['Observed events','request_started; upstream_response; timeout; flow_closed','Enumerated codes; no free-form raw errors'],['Response metadata','Status class; content-type category; size bucket','No body content, credentials, tokens or raw headers'],['Timing / completeness','Elapsed intervals; event count; missing-event flags','No oracle-derived completion indicators'],['Sequence structure','Event-order transitions; duration summaries','Only events available before window closure']],[95,192,166]),
 H('5.3 Dataset collection'),
 'Create three synthetic applications with different implementation styles and repeatable configurations. Collect normal, explicit-rejection, technical-fault and incomplete-observation episodes. Include benign slow conditions and failures in more than one application so labels do not collapse into application identity.',
 'Begin with a pilot; a provisional planning range is 300-600 complete episodes, not individual requests. Determine final sample size and class balance from pilot variance and annotation effort. Maintain application, scenario-family, collection-period and duplicate-group identifiers outside feature columns.',
 H('5.4 Privacy and label quality'),
 'Construct telemetry by allowlist, not by saving raw traffic and redacting later. Seed canary secrets in fixtures and scan all exports. Review a stratified sample of labels independently, record disagreements, and version corrections. Synthetic data is still subject to retention and access controls.')
P('5. Training and evaluation pipeline',
 F('5.1','Training pipeline with independent research labels',[
 ('gen',0,265,130,50,'Synthetic episodes\nKnown app + fault fixtures'),('obs',160,265,130,50,'Sanitized windows\nSeparate oracle labels'),('split',320,265,130,50,'Freeze grouped splits\nNo shared app in holdout'),('train',0,135,130,60,'Fit preprocessing +\ntrain model heads'),('val',160,135,130,60,'Validation: tune and\ncalibrate thresholds'),('test',320,135,130,60,'Frozen holdout: score\npredictions vs oracle'),('reg',160,15,130,60,'Versioned artifacts\nData / code / model hashes')],
 [('gen','obs','correlate offline'),('obs','split','versioned records'),('split','train','training groups'),('train','val','candidate'),('val','test','frozen model'),('test','reg','metrics + provenance')],h=330),
 H('5.5 Model progression'),
 'Implement explicit rules and a majority-class baseline first. Train logistic regression and gradient-boosted trees on window summaries. Add a small sequence model only if event ordering provides measurable benefit and sufficient data exists. An LLM chatbot or external API is not required.',
 'Use identical train/validation/test groups for all compared models. Fit preprocessing on training only. Handle class imbalance with training-only resampling or weights. Record hyperparameter search budget to avoid unfair comparisons.')
P('5. Uncertainty and explanation design',
 H('5.6 Calibration and abstention'),
 'Choose probability calibration and abstention thresholds using validation groups only. Require minimum evidence completeness before trusting the classifier. Report risk versus coverage: a system that abstains on almost every difficult episode must not appear superior through selective accuracy alone.',
 H('5.7 Evidence-linked explanations'),
 'Version 1 explanations are deterministic templates populated from observed event IDs and model output. Example: predicted failure category UPSTREAM; evidence contains connection-timeout event e17 and no terminal app response; confidence 0.72. Such a diagnosis is a prediction, not causal proof. This example is illustrative, not measured.',
 'Do not send raw credentials or unrestricted logs to an external model. If a future language layer is added, it may paraphrase structured records but cannot invent evidence IDs, upgrade confidence, change labels, or initiate actions.',
 H('5.8 Avoid trivial or leaked learning'),
 'If a timeout flag directly determines a label, a simple rule may be optimal. Keep that strong baseline and report results honestly. Test ambiguous and mixed observations separately, without artificially hiding useful features from rules. Do not include fault-injection names or application-specific identifiers that reveal labels.',
 H('5.9 Model provenance'),
 'Record code commit, dataset and split hashes, feature schema, label version, seeds, fitted preprocessing, hyperparameters, calibration configuration, model hash and hardware. Freeze model artifacts during evaluation. Never update weights from final-test outcomes.')

P('6. Technical implementation and code mapping',
 'The reviewed software baseline is Un-9oon/PhantomGate commit 8ae8437a4900b03fbaf187ac98bbde6127687efa [9]. The earlier documentation branch does not implement the AI system. Reinspect the supplied checkout and its instructions before editing; local code may have changed.',
 T('Table 6.1 - Existing files and proposed integration',['Existing path / symbol','Verified responsibility','Proposed change'],[['internal/proxy/proxy.go / ServeHTTP','Core request and response handling','Emit allowlisted metadata; never call inference inline'],['internal/proxy/proxy.go / ErrorHandler','Proxy error response handling','Emit normalized technical-error events'],['internal/config/config.go','Defaults and YAML loading','Add validated assistant/lab settings'],['cmd/phantomgate/main.go','Startup, listeners and signal handling','Wire optional worker; graceful shutdown'],['internal/store/store.go','Existing capture-oriented JSON store','Do not use captured secrets as AI training data'],['internal/api/server.go','API registration and lifecycle methods','Inspect wiring first; add only read-only diagnosis views']],[177,135,141]),
 H('6.1 Integration rule'),
 'Add isolated diagnosis modules rather than replacing the reverse proxy. Preserve documented forwarding behavior during instrumentation, and test regressions. General reliability fixes must not add payload-delivery, credential-collection, evasion or autonomous target-selection functionality.')
P('6. Proposed modules and implementation sequence',
 T('Table 6.2 - Proposed new modules',['Path','Responsibility'],[['internal/telemetry/','Allowlisted Event type, sanitizer, non-blocking EventSink'],['internal/diagnosis/','Window builder, prediction client, structured explanations'],['internal/evidence/','Redacted events, diagnosis persistence and export'],['ai/','Feature code, supervised training, calibration, local service'],['lab/','Synthetic apps, manifests, reset scripts and separate oracle'],['evaluation/','Split audit, baselines, metrics and overhead harness'],['docs/AI_HANDOVER.md + PROJECT_SPEC.json','Implementation intent and machine-readable scope']],[190,263]),
 H('6.2 Order of implementation'),
 B('M1: Inspect the baseline; run existing supported checks; create a reproducible synthetic lab.', 'M2: Define schemas and sanitizer; prove secret-canary removal and non-blocking event emission.', 'M3: Implement windowing, independent oracle fixtures, evidence store and rule baseline.', 'M4: Collect a pilot dataset; freeze labels and grouped splits; train simple classifiers.', 'M5: Add the local read-only assistant and explicit degraded states.', 'M6: Run held-out diagnosis and proxy reliability experiments; update measured report sections.'),
 H('6.3 First usable milestone'),
 'One synthetic application, a redacted event trace, one closed window, a rules-based diagnosis, and an independently verified label. Model complexity comes after this end-to-end evidence pipeline works.')
P('6. Interface and configuration contracts',
 T('Table 6.3 - Proposed local diagnostic interface',['Interface','Request / result','Failure behavior'],[['POST /v1/diagnose','schema_version, model_id, window_id, sanitized events','Typed result; deadline; no execution commands'],['GET /healthz','Service health only','No sensitive model or event content'],['GET /readyz','Loaded model and schema compatibility','Not ready if artifact invalid'],['TryEmit(event) -> bool','Non-blocking, sanitized typed event','False on saturation; increment loss counters']],[105,216,132]),
 H('6.4 Version 1 envelope'),
 'A diagnosis returns schema_version, model_id, flow_id, window_id, status, predicted_outcome, predicted_failure, outcome_confidence, failure_confidence, abstain_reason and evidence_event_ids. Confidence fields are null for UNAVAILABLE or INVALID_INPUT. Class probabilities must be finite and bounded. Reject duplicate IDs and unknown schema versions.',
 H('6.5 Proposed defaults - subject to pilot'),
 'Assistant disabled by default; loopback service URL; maximum 10,000 queued events; maximum 256 events or 60 seconds per window; 5-second idle closure; 250 ms inference deadline; bounded workers and at most one retry outside the forwarding path. These numbers are design defaults, not performance claims. Track every dropped event and set affected windows incomplete.',
 H('6.6 Persistence'),
 'Use a separate transactional SQLite evidence database as the initial design, with one writer and immutable read snapshots. Select the Go driver after checking supported OS, CGO requirements and dependency policy. Persist only redacted records and propagate storage failures explicitly.')
P('6. Reliability engineering and degraded behavior',
 T('Table 6.4 - Reliability work',['Area','Required behavior','Verification'],[['Timeouts','Explicit server, upstream and worker deadlines','Slow upstream and idle-client fixtures'],['Concurrency','Clear ownership; immutable snapshots','Reader/writer stress and race checks'],['Queues','Bound capacity; never block proxy on inference','Model hang + queue saturation'],['Storage','Transactions and recovery of committed records','Interrupt writer; reopen; check integrity'],['Shutdown','Stop intake; cancel; bounded drain; cleanup status','Signal and forced-stop tests'],['Model integrity','Pinned trusted artifact and schema','Hash mismatch and invalid-input tests'],['Observability','Counters for loss, failures and inference status','Metrics match injected conditions']],[81,218,154]),
 H('6.7 Limits of AI assistance'),
 'The assistant can improve interpretation only if measurements demonstrate it. It cannot repair unsafe concurrency or establish correctness of forwarding by prediction. Separate regression and reliability tests are mandatory. The earlier report\'s zero-latency and production-ready claims are withdrawn.',
 'When storage fails, report degradation; do not manufacture missing evidence. When the model fails, continue authorized forwarding without diagnosis or stop according to explicit operator configuration. Do not silently relabel predictions using a fallback while presenting them as model output.')

P('7. Evaluation methodology',
 H('7.1 Experimental design'),
 'Use three independently implemented synthetic applications. Hold out one entire application for testing, rotate it, and report each fold separately. Within remaining applications, group configuration families, collection periods and near-duplicates before splitting training and validation. If architecture decisions are made after inspecting rotated folds, obtain an additional untouched holdout for a final generalization claim.',
 H('7.2 Fair baselines'),
 'Compare majority-class prediction, explicit error/status rules, logistic regression and gradient-boosted trees. Include a sequence model only when justified. Every baseline sees the same allowed observations and window boundaries. The rule baseline is allowed to use informative error codes; do not weaken it to favor AI.',
 H('7.3 Ground-truth evaluation'),
 'Freeze predictions before joining oracle labels. Score outcome and failure heads separately, and report joint correctness. Keep unknown and multi-fault cases visible. The model must not be scored against its own explanation or against labels derived solely from its input error code.',
 H('7.4 Statistics and reproducibility'),
 'Use paired episodes and bootstrap confidence intervals resampling independent scenario families rather than correlated requests. Determine sample sizes from the pilot. Report seeds, prevalence, class counts, exclusions and all failed runs. Do not tune thresholds on the final holdout.',
 H('7.5 Ablations'),
 'Remove timing features, remove event order, disable calibration, and vary missing-event rate. Evaluate the privacy-minimal feature set against a broader metadata-only set. Never expose secrets or oracle fields as an ablation.')
P('7. Metrics and acceptance tests',
 T('Table 7.1 - Measures of success',['Dimension','Metric','Interpretation'],[['Diagnostic correctness','Per-class precision/recall; macro-F1; confusion matrices','Avoid majority-class accuracy alone'],['Joint prediction','Both heads correct per episode','Report UNKNOWN and abstentions explicitly'],['Uncertainty','Calibration score; selective risk vs coverage','Accuracy gain must disclose abstention cost'],['Generalization','Per-held-out-app scores and confidence intervals','Do not infer internet-wide validity'],['Runtime impact','Proxy p50/p95/p99; throughput; CPU/RAM','Paired AI-off/on at identical workload'],['Degradation','Drop rate; queue depth; outage behavior','Bounded resources and explicit missing data']],[105,190,158]),
 H('7.6 Minimum acceptance scenarios'),
 'Test successful and rejected lab flows; verified proxy/upstream/client faults; incomplete telemetry; invalid schema; model outage; queue saturation; storage interruption; concurrent windows; cancellation; and post-remediation retests. These are planned tests, not completed validation.',
 H('7.7 Results status'),
 'No proposed model has been trained or evaluated in this documentation revision. No diagnostic accuracy, overhead improvement or robustness pass rate is available. The final submission must replace planned-result wording with measured tables, logs, plots and failure analyses.')

P('8. Market value and practical feasibility',
 H('8.1 Intended users and value hypothesis'),
 'Potential users are university security labs, penetration-testing training teams and internal assessment engineers working on authorized applications. The value hypothesis is less manual trace interpretation, fewer unsupported conclusions, repeatable teaching experiments and clearer evidence handover. These are proposed benefits, not verified customer demand or revenue projections.',
 T('Table 8.1 - Positioning and alternatives',['Alternative','Existing value','Proposed differentiator to test'],[['Generic AI pentesting agents [1,2]','Broad assessment planning and automation','Focused evidence-linked proxy diagnosis'],['General log-analysis systems [5,6]','Anomaly or failure analysis','Authentication-specific labels and lab oracle'],['Manual proxy/log review','Expert interpretation and flexibility','Repeatable assistant with measured uncertainty'],['Rules-only diagnostic layer','Transparent and inexpensive','Learned model only if it adds measured value']],[139,150,164]),
 H('8.2 Market validation plan'),
 'Interview a small approved sample of instructors and assessment engineers using synthetic traces. Compare interpretation time, error rate and perceived usefulness with and without the assistant in a counterbalanced task. Obtain required institutional approval before human-subject studies. Treat usability work as optional if the FYP schedule is limited.',
 H('8.3 Feasibility and costs'),
 'A local CPU workstation is the initial target; a GPU and external LLM API are not required. Record actual hardware, compute time, storage, dependency licenses and annotation effort. No market-size, pricing, cost-saving or commercial-readiness figure is asserted.')
P('9. Project management and risk register',('gantt',),
 T('Table 9.1 - Relative milestone plan',['Weeks','Milestone','Exit criterion'],[['1-2','Scope and literature','Approved protocol and label taxonomy'],['3-4','Telemetry and independent oracle','One end-to-end synthetic fixture'],['5-6','Dataset and rule baseline','Split audit and reviewed pilot labels'],['7-8','Train and embed model','Reproducible model and degraded states'],['9-10','Evaluate and harden','Held-out metrics and fault-test records'],['11-12','Report and handover','Independent rebuild and evidence-linked demo']],[45,174,234]),
 H('9.1 Principal risks'),
 'Label leakage, insufficient classes, app-identity shortcuts, noisy fault attribution, no ML gain, incomplete telemetry, and schedule pressure are the main research risks. Mitigate through group holdouts, provenance, strong rules, explicit UNKNOWN labels, observable loss and a tabular-model-first plan. Do not compensate for weak results by expanding into payload automation.')
P('10. Conclusion and future work',
 H('10.1 Conclusion'),
 'PhantomGate-AI retains the reverse proxy as its core and embeds a trained observational assistant. Its candidate research contribution is evidence-grounded authentication-outcome and technical-failure diagnosis under application shift, sanitized inputs and uncertain observations. Conventional engineering establishes forwarding reliability separately from predictive performance.',
 'The expected FYP deliverables are an instrumented proxy, bounded telemetry pipeline, independent lab oracle, labeled dataset, trained models, local assistant, comparative evaluation and reproducible handover. This document specifies the intended system but does not claim that the implementation or experiments are complete.',
 H('10.2 Future work after the initial evaluation'),
 B('Extend to more independently implemented lab applications and authentication workflows.', 'Investigate small temporal models if summary-feature models miss ordering information.', 'Evaluate distribution-shift monitoring and controlled retraining with new validation data.', 'Improve multi-fault labels and distinguish observed correlation from experimentally established cause.', 'Add locally generated natural-language explanations constrained to structured evidence.', 'Conduct approved operator usability studies and evaluate interoperability with observability tools.'),
 H('10.3 Limits on the final claims'),
 'A successful FYP need not prove a globally new algorithm. It must identify its original work, justify the candidate gap and report honest results. General failure diagnosis and AI pentesting already exist. No claim of complete gap closure, universal novelty or production robustness is justified before the review and measurements support it.')

P('11. Implementation handover - read this first',
 H('11.1 Binding scope for a receiving AI or developer'),
 'Build PhantomGate-AI as specified here: a Go reverse proxy with an optional, read-only, student-trained diagnostic assistant. Implement outcome/failure classification, uncertainty and evidence-linked reporting. Do not substitute the superseded next-action-selection agent or a generic phishing detector.',
 T('Table 11.1 - Source-of-truth hierarchy',['Order','Artifact','Meaning'],[['1','Latest explicit human instruction','Clarifies or changes authorized project scope'],['2','This revision + docs/AI_HANDOVER.md','Current design and implementation roadmap'],['3','PROJECT_SPEC.json','Machine-readable taxonomy and interfaces'],['4','Inspected checkout and its repository instructions','Actual existing symbols and constraints'],['5','Earlier report / README claims','Historical context; verify rather than assume']],[40,190,223]),
 H('11.2 First actions after receiving the code'),
 'Read repository instructions and inspect git status. Identify the actual commit and compare it with baseline [9]. Read proxy.go, config.go, main.go and relevant tests. Record which existing checks can run on the host. Establish the minimal synthetic fixture and telemetry contract before model code. Keep unrelated user changes intact.',
 H('11.3 Definition of a correct first increment'),
 'The proxy still forwards the synthetic interaction with the assistant disabled. Enabling event capture adds only allowlisted metadata. A slow or missing model does not block forwarding. A single flow produces an auditable redacted window, rule diagnosis and independent label. No credentials or token values appear in exported training data.')
P('11. Handover - data contract and edge cases',
 T('Table 11.2 - Version 1 event envelope',['Field','Type / rule','Model usage'],[['schema_version','Constant pg.telemetry.v1','Compatibility check only'],['run_id / flow_id / event_id','Opaque non-secret strings; unique event ID','Grouping/evidence only'],['sequence / elapsed_ms','Monotonic sequence; non-negative finite duration','Ordering and timing'],['kind','Validated event enumeration','Feature'],['status_class / error_code','Optional normalized enums','Feature; strong rule baseline'],['size_bucket / content_type','Optional allowlisted categories','Feature'],['completeness','Missing count; drop indicator; closure reason','Feature / abstention gate']],[134,182,137]),
 H('11.4 Correlation and missingness'),
 'Correlate events using a controller-issued opaque flow identifier carried only in the lab context. Never hash secret tokens as a shortcut. If correlation is unavailable or ambiguous, keep events in an unassigned/unknown window instead of joining different users. Reject client-provided IDs outside the expected format.',
 H('11.5 Window semantics'),
 'A window is a bounded observed portion of one flow. Multiple windows may belong to a flow; all remain in the same dataset split. Terminal observations, idle closure and telemetry loss are separate fields. A closure timeout does not imply authentication rejection. Late events follow a versioned policy: append to a new linked window and mark the earlier prediction as partial, without rewriting history.')
P('11. Handover - example record and testing map',
 H('11.6 Illustrative output - not an experimental result'),
 'Example identity: schema pg.diagnosis.v1; model demo-model; flow lab-flow-001; status ABSTAINED; predicted outcome UNKNOWN; predicted failure UNKNOWN; abstain reason MISSING_TERMINAL_EVIDENCE; evidence IDs e01 and e03. This demonstrates the contract only. No trained confidence or measured performance is implied.',
 T('Table 11.3 - Required implementation checks',['Test ID','Behavior','Completion evidence'],[['T01','Assistant off preserves lab forwarding','Regression fixture and response assertions'],['T02','Canary secrets absent before queue/export','Schema and artifact scans'],['T03','Full queue never blocks ServeHTTP','Saturation timing and loss counters'],['T04','Windows never cross flow boundaries','Interleaved concurrent fixtures'],['T05','Oracle fields never reach inference','Feature-allowlist and access-boundary tests'],['T06','Model outage has explicit status','UNAVAILABLE record; forwarding still operates'],['T07','Predictions reference existing events','Foreign-key and report checks'],['T08','Held-out applications remain unseen','Immutable split manifest and duplicate audit'],['T09','Committed records recover after crash','Integrity checks on reopened evidence store'],['T10','Stop cancels and drains within bounds','Shutdown timing and cleanup status']],[37,229,187]),
 'All checks above are pending implementation. Save actual commands, environment information and results when they run. Do not copy the old report\'s claimed test passes into this revision as evidence.')

refs=[
('[1]','G. Deng et al. PentestGPT: Evaluating and Harnessing Large Language Models for Automated Penetration Testing. USENIX Security, pp. 847-864, 2024.','https://www.usenix.org/conference/usenixsecurity24/presentation/deng'),
('[2]','Y. Ginige, A. Niroshan, S. Jain, and S. Seneviratne. AutoPentester: An LLM Agent-based Framework for Automated Pentesting. arXiv:2510.05605, 2025; record lists IEEE TrustCom 2025.','https://arxiv.org/abs/2510.05605'),
('[3]','B. Kondracki, B. Amin Azad, O. Starov, and N. Nikiforakis. Catching Transparent Phish: Analyzing and Detecting MITM Phishing Toolkits. ACM CCS, 2021. DOI 10.1145/3460120.3484765.','https://briankondracki.com/assets/pdf/catching_transparent_phish.pdf'),
('[4]','E. Ulqinaku, H. Assal, A. Abdou, S. Chiasson, and S. Capkun. Is Real-time Phishing Eliminated with FIDO? Social Engineering Downgrade Attacks against FIDO Protocols. USENIX Security, pp. 3811-3828, 2021.','https://www.usenix.org/conference/usenixsecurity21/presentation/ulqinaku'),
('[5]','H. Guo, S. Yuan, and X. Wu. LogBERT: Log Anomaly Detection via BERT. arXiv:2103.04475, 2021. Cited author manuscript.','https://arxiv.org/abs/2103.04475'),
('[6]','T. Wittkopp, P. Wiesner, and O. Kao. LogRCA: Log-based Root Cause Analysis for Distributed Services. arXiv:2405.13599, 2024; accepted at Euro-Par 2024 according to the author record.','https://arxiv.org/abs/2405.13599'),
('[7]','K. Scarfone, M. Souppaya, A. Cody, and A. Orebaugh. Technical Guide to Information Security Testing and Assessment. NIST SP 800-115, 2008. Assessment guidance.','https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf'),
('[8]','W3C. Web Authentication: An API for accessing Public Key Credentials - Level 2. W3C Recommendation, 8 April 2021. Specification.','https://www.w3.org/TR/webauthn-2/'),
('[9]','Un-9oon/PhantomGate. Existing source framework. Baseline commit 8ae8437a4900b03fbaf187ac98bbde6127687efa. Software artifact, not a paper.','https://github.com/Un-9oon/PhantomGate/tree/8ae8437a4900b03fbaf187ac98bbde6127687efa')]
P('References',*['%s %s<br/><link href="%s" color="%s">%s</link>'%(i,html.escape(t),u,BLUE,u) for i,t,u in refs[:5]],'Primary-source review checked on 22 October 2026. Source categories and limits are stated explicitly; this is not an exhaustive systematic review.')
P('References - continued',*['%s %s<br/><link href="%s" color="%s">%s</link>'%(i,html.escape(t),u,BLUE,u) for i,t,u in refs[5:]],
 H('Assessment guidance'),
 'NIST SP 800-115 [7] informs authorization, planning, evidence analysis and reporting. Citing guidance does not certify this project or prove compliance. Independent verification and documented boundaries remain implementation requirements.')
P('Appendix A. Submission and reproducibility checklist',
 B('Complete student, institution, supervisor and academic-session details; obtain real signatures.', 'Apply the institution\'s cover, margin, approval, binding and reference requirements.', 'Keep this report, AI_HANDOVER.md and PROJECT_SPEC.json consistent.', 'Credit existing code and identify student-authored contributions.', 'Freeze dataset, labels, splits, model and code versions before final evaluation.', 'Attach actual per-class results, uncertainty curves, overhead measurements and reliability logs.', 'Record failed runs and negative results; do not claim novelty solely from AI integration.', 'Rebuild the PDF and inspect every rendered page after substantive edits.', 'Give the receiving AI the current code snapshot, this report, handover and specification together.'),
 H('Suggested receiving-AI prompt'),
 'Read the report, docs/AI_HANDOVER.md and PROJECT_SPEC.json first. Summarize the fixed scope and current implementation status. Inspect the actual checkout and repository instructions. Keep PhantomGate as the reverse proxy and implement the observational diagnosis pipeline incrementally. Begin with schemas, redaction, a synthetic fixture and independent labels. Do not replace the project with an action-selection agent or claim unrun tests and unmeasured results.',
 H('Status at handover'),
 'Documentation and diagram assets are delivered. Proposed runtime modules, lab extensions, data collection, model training and evaluation remain to be implemented and verified.')

class Sequence(Flowable):
    def __init__(self):
        Flowable.__init__(self);self.width=W;self.height=360
        xs=[40,135,230,325,420];names=['Browser','Go proxy','Worker','AI service','Evidence']
        s=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="360"><rect width="100%" height="100%" fill="white"/>']
        for x,name in zip(xs,names):s.extend([f'<rect x="{x-38}" y="15" width="76" height="30" rx="3" fill="{PALE}" stroke="{BLUE}"/>',f'<text x="{x}" y="33" text-anchor="middle" font-family="Arial" font-size="8">{name}</text>',f'<line x1="{x}" y1="50" x2="{x}" y2="350" stroke="{BLUE}" stroke-dasharray="3 3"/>'])
        msgs=[(0,1,'Synthetic lab request'),(1,0,'Forwarded app response'),(1,2,'Non-blocking sanitized event'),(2,3,'Closed observed window'),(3,2,'Prediction or abstention'),(2,4,'Persist diagnosis + evidence'),(2,4,'Outage: explicit unavailable'),(1,2,'Stop: bounded drain')]
        for i,(a,b,t) in enumerate(msgs):
            y=73+i*30;sgn=1 if xs[b]>xs[a] else -1
            s.extend([f'<path d="M {xs[a]} {y} H {xs[b]} M {xs[b]-sgn*5} {y-3} L {xs[b]} {y} L {xs[b]-sgn*5} {y+3}" fill="none" stroke="{BLUE}"/>',f'<text x="{(xs[a]+xs[b])/2}" y="{y-6}" text-anchor="middle" font-family="Arial" font-size="7.5">{html.escape(t)}</text>'])
        s.append('</svg>');(DIAG/'figure-4-8.svg').write_text('\n'.join(s),encoding='utf-8')
    def draw(self):
        c=self.canv;xs=[40,135,230,325,420];names=['Browser','Go proxy','Worker','AI service','Evidence']
        for x,name in zip(xs,names):
            c.setFillColor(colors.HexColor(PALE));c.setStrokeColor(colors.HexColor(BLUE));c.roundRect(x-38,315,76,30,3,fill=1);c.setFillColor(colors.HexColor(NAVY));c.setFont('Helvetica-Bold',8);c.drawCentredString(x,327,name);c.setDash(3,3);c.line(x,310,x,10);c.setDash()
        msgs=[(0,1,'Synthetic lab request'),(1,0,'Forwarded app response'),(1,2,'Non-blocking sanitized event'),(2,3,'Closed observed window'),(3,2,'Prediction or abstention'),(2,4,'Persist diagnosis + evidence'),(2,4,'Outage: explicit unavailable'),(1,2,'Stop: bounded drain')]
        for i,(a,b,t) in enumerate(msgs):
            y=287-i*30;c.setStrokeColor(colors.HexColor(BLUE));c.line(xs[a],y,xs[b],y);sgn=1 if xs[b]>xs[a] else -1;c.line(xs[b],y,xs[b]-sgn*5,y+3);c.line(xs[b],y,xs[b]-sgn*5,y-3);c.setFont('Helvetica',7.5);c.setFillColor(colors.HexColor(NAVY));c.drawCentredString((xs[a]+xs[b])/2,y+6,t)

class Gantt(Flowable):
    def __init__(self):
        Flowable.__init__(self);self.width=W;self.height=185
        s=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="185"><rect width="100%" height="100%" fill="white"/>']
        for w in range(12):s.append(f'<text x="{125+w*26+13}" y="15" text-anchor="middle" font-family="Arial" font-size="8">{w+1}</text>')
        for i,label in enumerate(['Scope + literature','Telemetry + oracle','Dataset + rules','Train + embed','Evaluate + harden','Report + handover']):
            y=26+i*25;s.append(f'<text x="0" y="{y+13}" font-family="Arial" font-size="8">{label}</text>')
            for w in range(12):s.append(f'<rect x="{125+w*26}" y="{y}" width="26" height="19" fill="white" stroke="#D7E0E5"/>')
            s.append(f'<rect x="{125+i*52}" y="{y+1}" width="52" height="17" fill="{BLUE}"/>')
        s.append('</svg>');(DIAG/'figure-9-1.svg').write_text('\n'.join(s),encoding='utf-8')
    def draw(self):
        c=self.canv;labels=['Scope + literature','Telemetry + oracle','Dataset + rules','Train + embed','Evaluate + harden','Report + handover'];left=125;cw=26
        c.setFont('Helvetica',8)
        for w in range(12):c.drawCentredString(left+w*cw+cw/2,170,str(w+1))
        for i,label in enumerate(labels):
            y=140-i*25;c.setFillColor(colors.HexColor(NAVY));c.drawString(0,y+6,label)
            for w in range(12):c.setStrokeColor(colors.HexColor('#D7E0E5'));c.rect(left+w*cw,y,cw,19,stroke=1,fill=0)
            c.setFillColor(colors.HexColor(BLUE));c.rect(left+i*2*cw,y+1,2*cw,17,stroke=0,fill=1)

def roman(n):
    vals=[(10,'x'),(9,'ix'),(5,'v'),(4,'iv'),(1,'i')];s=''
    for v,t in vals:
        while n>=v:s+=t;n-=v
    return s
def page_label(i):return '' if i==1 else roman(i-1) if i<=5 else str(i-5)
for pi,(title,blocks) in enumerate(pages,1):
    for b in blocks:
        if isinstance(b,tuple) and b[0]=='f':figs.append((b[1],b[2],pi))
        elif isinstance(b,tuple) and b[0]=='t':tabs.append((b[1],pi))
        elif isinstance(b,tuple) and b[0]=='sequence':figs.append(('4.8','Assessment interaction sequence',pi))
        elif isinstance(b,tuple) and b[0]=='gantt':figs.append(('9.1','Proposed twelve-week schedule',pi))

story=[]
def add_md_table(headers,rows):
    md.append('| '+' | '.join(headers)+' |\n| '+' | '.join(['---']*len(headers))+' |')
    for row in rows:md.append('| '+' | '.join(str(x).replace('|','/') for x in row)+' |')
for pi,(title,blocks) in enumerate(pages,1):
    if pi>1:story.append(PageBreak())
    md.append('\n# '+title+'\n')
    if pi!=1:story.append(para(title,'H1F'))
    for block in blocks:
        if isinstance(block,str):story.append(para(block));md.append(re.sub('<[^>]+>','',html.unescape(block))+'\n');continue
        kind=block[0]
        if kind=='h':story.append(para(block[1],'H2F'));md.append('## '+block[1]+'\n')
        elif kind=='b':
            for x in block[1]:story.append(para('&#8226; '+x));md.append('- '+x)
        elif kind=='t':
            _,cap,heads,rows,widths=block;story.extend([para(cap,'CaptionF'),table(heads,rows,widths),Spacer(1,12)]);md.append('**'+cap+'**');add_md_table(heads,rows)
        elif kind=='f':
            _,num,cap,nodes,edges,height,notes=block;key='figure-'+num.replace('.','-');story.extend([Diagram(key,cap,nodes,edges,height,notes),para('Figure '+num+' - '+cap+'. Proposed design.','CaptionF')]);md.append(f'![Figure {num} - {cap}](diagrams/{key}.svg)\n')
        elif kind=='cover':
            story.extend([Spacer(1,40),para('FINAL YEAR PROJECT | REVISED DESIGN REPORT','SmallF'),Spacer(1,35),para('PhantomGate-AI','CoverF'),para('Reverse Proxy with an AI Assistant for Authentication Outcome and Failure Diagnosis','SubF'),Spacer(1,25),para('Penetration Testing + Artificial Intelligence','H2F'),Spacer(1,20),para('Core system: the reverse proxy. AI contribution: evidence-grounded outcome and technical-failure diagnosis from sanitized laboratory observations.'),Spacer(1,65),table(['Submission information','Status'],[['Student(s) / registration ID(s)','Not supplied'],['University / department / degree','Not supplied'],['Supervisor / academic session','Not supplied'],['Revision / prepared','3.0 - FYP design and handover / 22 October 2026']],[210,243]),Spacer(1,28),para('Existing framework acknowledged. New AI and reliability modules are proposed. No experimental results are claimed.','SmallF')]);md.extend(['**Reverse Proxy with an AI Assistant for Authentication Outcome and Failure Diagnosis**','Revision 3.0 - FYP design and handover. Prepared 22 October 2026.','Team, university, department, degree, supervisor and academic session: not supplied.'])
        elif kind=='toc':
            rows=[]
            for j,(tt,_) in enumerate(pages,1):
                if j in [2,3,5] or (j>=6 and (j==6 or tt.split(' - ')[0]!=pages[j-2][0].split(' - ')[0])):
                    # Collapse chapter continuations to chapter starts.
                    if j>=6 and not (re.match(r'^\d+\. ',tt) and (j==6 or tt.split('.')[0]!=pages[j-2][0].split('.')[0])) and not tt.startswith(('References','Appendix')):continue
                    if tt=='References - continued':continue
                    rows.append([tt,page_label(j)])
            story.append(table(['Section','Page'],rows,[403,50]));story.extend([Spacer(1,18),para('Page numbering: preliminary pages use Roman numerals; main text and appendices use Arabic numerals. Figures are conceptual proposed designs unless explicitly stated otherwise.','SmallF')])
            add_md_table(['Section','Page'],rows)
        elif kind=='lists':
            text='<b>Figures</b><br/>'+'<br/>'.join(f'{n} {html.escape(t)} <b>{page_label(p)}</b>' for n,t,p in figs)
            story.append(para(text,'SmallF'));story.append(Spacer(1,7))
            story.append(para('<b>Tables</b><br/>'+'<br/>'.join(f'{html.escape(t)} <b>{page_label(p)}</b>' for t,p in tabs),'SmallF'))
            story.append(para('<b>Abbreviations</b><br/>AI: Artificial Intelligence; AiTM: Adversary-in-the-Middle; DFD: Data Flow Diagram; ERD: Entity Relationship Diagram; FYP: Final Year Project; ML: Machine Learning; RCA: Root Cause Analysis; SSO: Single Sign-On; MFA: Multi-Factor Authentication; PK/FK: Primary/Foreign Key.','SmallF'))
            add_md_table(['Figure','Title','Page'],[[n,t,page_label(p)] for n,t,p in figs])
            add_md_table(['Table','Page'],[[t,page_label(p)] for t,p in tabs])
            md.append('AI: Artificial Intelligence; AiTM: Adversary-in-the-Middle; DFD: Data Flow Diagram; ERD: Entity Relationship Diagram; FYP: Final Year Project; ML: Machine Learning; RCA: Root Cause Analysis; SSO: Single Sign-On; MFA: Multi-Factor Authentication; PK/FK: Primary/Foreign Key.')
        elif kind=='sequence':story.extend([Sequence(),para('Figure 4.8 - Assessment interaction sequence. Proposed design.','CaptionF')]);md.append('![Figure 4.8 - Assessment interaction sequence](diagrams/figure-4-8.svg)')
        elif kind=='gantt':story.extend([Gantt(),para('Figure 9.1 - Proposed twelve-week schedule; relative weeks, not calendar commitments.','CaptionF')]);md.append('![Figure 9.1 - Proposed twelve-week schedule](diagrams/figure-9-1.svg)')

def footer(c,doc):
    i=doc.page;c.saveState()
    c.bookmarkPage('page-'+str(i));c.addOutlineEntry(pages[i-1][0],'page-'+str(i),level=0,closed=False)
    if i>1:
        c.setStrokeColor(colors.HexColor('#D7E0E5'));c.line(78,48,531,48);c.setFont('Helvetica',8);c.setFillColor(colors.HexColor(GRAY));c.drawString(78,35,'PHANTOMGATE-AI | DESIGN PROPOSAL');c.drawRightString(531,35,page_label(i));c.setFont('Helvetica',7.5);c.drawString(78,805,'FINAL YEAR PROJECT - PENETRATION TESTING AND ARTIFICIAL INTELLIGENCE')
    else:
        c.setStrokeColor(colors.HexColor(BLUE));c.setLineWidth(3);c.line(63,85,63,750)
    c.restoreState()

doc=SimpleDocTemplate(str(OUT/'PhantomGate-Project-Report.pdf'),pagesize=A4,leftMargin=78,rightMargin=64,topMargin=60,bottomMargin=66,title='PhantomGate-AI: Reverse Proxy with an Embedded Diagnostic Assistant',author='PhantomGate project team - details pending',subject='Revised FYP design proposal; no measured results')
doc.build(story,onFirstPage=footer,onLaterPages=footer)
(OUT/'PhantomGate-Project-Report.md').write_text('\n'.join(md),encoding='utf-8')
reader=PdfReader(OUT/'PhantomGate-Project-Report.pdf')
print(json.dumps({'expected_pages':len(pages),'actual_pages':len(reader.pages),'figures':len(figs),'tables':len(tabs),'bytes':(OUT/'PhantomGate-Project-Report.pdf').stat().st_size}))
for i,p in enumerate(reader.pages,1):print(i, (p.extract_text() or '').splitlines()[1:3])
