import { clearSession } from './session.js?v=20261006-security1';

const THEME_KEY = 'dt_theme_pref';
const THEME_MODES = ['dark', 'light'];

const resolveTheme = () => {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === 'light' || saved === 'dark') {
        return saved;
    }

    return 'dark';
};

const applyTheme = (mode) => {
    document.body.classList.toggle('light', mode === 'light');
    localStorage.setItem(THEME_KEY, mode);
};

const updateActiveNav = () => {
    const page = document.body.dataset.page;
    document.querySelectorAll('.nav-link[data-page]').forEach((link) => {
        link.classList.toggle('active', link.dataset.page === page);
    });
};

const applyRiskBadge = () => {
    const badge = document.getElementById('globalRiskBadge');
    if (!badge) {
        return;
    }

    const score = Number(document.body.dataset.risk || 58);
    const level = score < 30 ? 'low' : score <= 60 ? 'medium' : 'high';
    badge.classList.remove('low', 'medium', 'high');
    badge.classList.add(level);
    badge.textContent = `Global Risk ${score} (${level.toUpperCase()})`;
};

const initThemeSwitch = () => {
    const toggle = document.getElementById('themeToggle');
    const ripple = document.getElementById('themeRipple');
    if (!toggle) {
        return;
    }

    let mode = resolveTheme();
    applyTheme(mode);
    toggle.textContent = mode === 'light' ? '🌗 Theme: Light' : '🌗 Theme: Dark';

    toggle.addEventListener('click', (event) => {
        const currentIndex = THEME_MODES.indexOf(mode);
        mode = THEME_MODES[(currentIndex + 1) % THEME_MODES.length];
        applyTheme(mode);
        toggle.textContent = mode === 'light' ? '🌗 Theme: Light' : '🌗 Theme: Dark';

        if (ripple) {
            const rect = toggle.getBoundingClientRect();
            ripple.style.left = `${event.clientX - rect.left}px`;
            ripple.style.top = `${event.clientY - rect.top}px`;
            ripple.classList.remove('active');
            void ripple.offsetWidth;
            ripple.classList.add('active');
        }
    });
};

const initNotifications = () => {
    const button = document.getElementById('notifyBtn');
    const panel = document.getElementById('notifyPanel');
    if (!button || !panel) {
        return;
    }

    button.addEventListener('click', () => {
        panel.classList.toggle('show');
    });

    document.addEventListener('click', (event) => {
        if (!panel.contains(event.target) && !button.contains(event.target)) {
            panel.classList.remove('show');
        }
    });
};

const initProfileMenu = () => {
    const chip = document.getElementById('userChip');
    const menu = document.getElementById('profileMenu');
    const logout = document.getElementById('profileLogout');
    if (!chip || !menu) {
        return;
    }

    chip.addEventListener('click', () => {
        menu.classList.toggle('show');
    });

    logout?.addEventListener('click', () => {
        clearSession('manual-logout');
    });

    document.addEventListener('click', (event) => {
        if (!chip.contains(event.target) && !menu.contains(event.target)) {
            menu.classList.remove('show');
        }
    });
};

const initSearch = () => {
    const search = document.getElementById('globalSearch');
    const status = document.getElementById('pageStatus');
    if (!search || !status) {
        return;
    }

    search.addEventListener('input', () => {
        if (!search.value.trim()) {
            status.textContent = 'System healthy. All trust services operational.';
            return;
        }

        status.textContent = `Searching platform for "${search.value.trim()}"...`;
    });
};

const initToggles = () => {
    document.querySelectorAll('[data-toggle]').forEach((toggle) => {
        toggle.addEventListener('click', () => {
            toggle.classList.toggle('on');
        });
    });
};

const initTrendChart = () => {
    const chart = document.getElementById('riskTrendChart');
    if (!chart) {
        return;
    }

    chart.innerHTML = '';
    const points = [35, 48, 42, 55, 38, 44, 32];
    points.forEach((value) => {
        const bar = document.createElement('span');
        bar.style.height = `${value}px`;
        chart.appendChild(bar);
    });
};

const initLogout = () => {
    const button = document.getElementById('logoutBtn');
    if (!button) {
        return;
    }

    button.addEventListener('click', () => {
        clearSession('manual-logout');
    });
};

document.addEventListener('DOMContentLoaded', () => {
    updateActiveNav();
    initThemeSwitch();
    applyRiskBadge();
    initNotifications();
    initSearch();
    initToggles();
    initTrendChart();
    initProfileMenu();
    initLogout();
});
