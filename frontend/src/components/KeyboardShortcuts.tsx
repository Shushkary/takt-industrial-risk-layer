// Глобальные hotkeys для keyboard-first навигации

import { useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useCaseStore } from '../stores/caseStore';

interface KeyboardShortcutsProps {
  cases?: { id: string }[];
}

export function KeyboardShortcuts({ cases = [] }: KeyboardShortcutsProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const { focusedIndex, incrementFocus, decrementFocus, setFocusedIndex } = useCaseStore();
  
  useEffect(() => {
    // Только на странице очереди инцидентов
    if (location.pathname !== '/') return;
    
    const handleKeyDown = (e: KeyboardEvent) => {
      // Игнорировать, если фокус в input/textarea
      if (
        e.target instanceof HTMLInputElement ||
        e.target instanceof HTMLTextAreaElement
      ) {
        return;
      }
      
      switch (e.key) {
        case 'j': // Следующий кейс
          e.preventDefault();
          if (focusedIndex < cases.length - 1) {
            incrementFocus();
          }
          break;
        
        case 'k': // Предыдущий кейс
          e.preventDefault();
          if (focusedIndex > 0) {
            decrementFocus();
          }
          break;
        
        case 'Enter': // Открыть выбранный кейс
          e.preventDefault();
          if (cases[focusedIndex]) {
            navigate(`/case/${cases[focusedIndex].id}`);
          }
          break;
      }
    };
    
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [location.pathname, focusedIndex, cases, incrementFocus, decrementFocus, navigate]);
  
  // Сброс фокуса при изменении списка кейсов
  useEffect(() => {
    setFocusedIndex(0);
  }, [cases.length, setFocusedIndex]);
  
  return null; // Компонент без визуального отображения
}
