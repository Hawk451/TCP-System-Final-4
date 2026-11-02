/**
 * site.js — SkyForce Aviation Test Website
 * Handles: nav scroll, fleet filtering, form submission, mobile menu
 */

'use strict';

// ── Sticky nav shrink on scroll ────────────────────────────────────────────
window.addEventListener('scroll', () => {
    const nav = document.getElementById('nav');
    if (window.scrollY > 60) {
        nav.classList.add('scrolled');
    } else {
        nav.classList.remove('scrolled');
    }
});

// ── Mobile menu toggle ─────────────────────────────────────────────────────
function toggleMenu() {
    document.querySelector('.nav__links').classList.toggle('open');
}

// Close menu on link click
document.querySelectorAll('.nav__links a').forEach(link => {
    link.addEventListener('click', () => {
        document.querySelector('.nav__links').classList.remove('open');
    });
});

// ── Fleet filter ───────────────────────────────────────────────────────────
function filterFleet(type, btn) {
    // Update active tab
    document.querySelectorAll('.fleet-tab').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');

    // Show/hide cards
    document.querySelectorAll('.aircraft-card').forEach(card => {
        if (type === 'all' || card.dataset.type === type) {
            card.classList.remove('hidden');
        } else {
            card.classList.add('hidden');
        }
    });
}

// ── Contact form ───────────────────────────────────────────────────────────
function handleSubmit(e) {
    e.preventDefault();
    const btn     = e.target.querySelector('button[type="submit"]');
    const success = document.getElementById('formSuccess');

    btn.textContent = 'Sending...';
    btn.disabled    = true;

    // Simulate submission delay
    setTimeout(() => {
        success.classList.remove('hidden');
        e.target.reset();
        btn.textContent = 'Send Enquiry ✈';
        btn.disabled    = false;

        // Hide success message after 5 seconds
        setTimeout(() => success.classList.add('hidden'), 5000);
    }, 1000);
}

// ── Smooth scroll for anchor links ────────────────────────────────────────
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        const href = this.getAttribute('href');
        // A bare "#" link (footer placeholders) is not a valid selector — ignore it
        if (href === '#') { e.preventDefault(); return; }
        const target = document.querySelector(href);
        if (target) {
            e.preventDefault();
            const offset = 80; // nav height
            const top    = target.getBoundingClientRect().top + window.pageYOffset - offset;
            window.scrollTo({ top, behavior: 'smooth' });
        }
    });
});

// ── Fade-in on scroll (simple intersection observer) ──────────────────────
const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.opacity    = '1';
            entry.target.style.transform  = 'translateY(0)';
        }
    });
}, { threshold: 0.1 });

document.querySelectorAll('.aircraft-card, .service-card, .about__card').forEach(el => {
    el.style.opacity    = '0';
    el.style.transform  = 'translateY(20px)';
    el.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
    observer.observe(el);
});
