import { useEffect, useState } from 'react';

/** The page is one argument in six questions; the rail shows where you are in it. */
export const QUESTIONS = [
  { id: 'ask', text: 'Could a quantum computer log in as you?' },
  { id: 'how', text: 'How would that work?' },
  { id: 'fix', text: 'What stops it?' },
  { id: 'cost', text: 'Why hasn’t everyone switched?' },
  { id: 'switch', text: 'How do you switch safely?' },
  { id: 'real', text: 'Is any of this real?' },
];

export function Rail() {
  const [current, setCurrent] = useState('ask');

  useEffect(() => {
    // The current question is the last one whose top has passed the upper third of the screen.
    const update = () => {
      const line = window.innerHeight / 3;
      let active = QUESTIONS[0]!.id;
      for (const q of QUESTIONS) {
        const el = document.getElementById(q.id);
        if (el && el.getBoundingClientRect().top <= line) active = q.id;
      }
      setCurrent(active);
    };
    update();
    window.addEventListener('scroll', update, { passive: true });
    return () => window.removeEventListener('scroll', update);
  }, []);

  return (
    <nav className="rail" aria-label="Questions on this page">
      <ol>
        {QUESTIONS.map((q) => (
          <li key={q.id}>
            <a href={`#${q.id}`} aria-current={current === q.id ? 'step' : undefined}>
              {q.text}
            </a>
          </li>
        ))}
      </ol>
    </nav>
  );
}
