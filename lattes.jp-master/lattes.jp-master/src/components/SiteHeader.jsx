import { ArrowRight, List, X } from "@phosphor-icons/react";
import { useEffect, useState } from "react";

const navItems = [
  { label: "Works", href: "/#experiments" },
  { label: "About", href: "/#about" },
  { label: "Notes", href: "/#words" },
  { label: "Toolbox", href: "/toolbox" },
  { label: "Lvau", href: "/lvau" },
];

export function SiteHeader({ route, navigate, onContact }) {
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    setMenuOpen(false);
  }, [route]);

  function handleLink(event, href) {
    event.preventDefault();
    setMenuOpen(false);
    navigate(href);
  }

  return (
    <header className="site-header">
      <a
        className="wordmark"
        href="/"
        onClick={(event) => handleLink(event, "/")}
      >
        latte
      </a>

      <nav className="desktop-nav" aria-label="Primary navigation">
        {navItems.map((item) => (
          <a
            className={
              item.href === route ||
              (item.href === "/lvau" && route.startsWith("/lvau"))
                ? "nav-link nav-link--active"
                : "nav-link"
            }
            href={item.href}
            key={item.label}
            onClick={(event) => handleLink(event, item.href)}
          >
            {item.label}
          </a>
        ))}
      </nav>

      <div className="header-actions">
        <button className="nav-link contact-button" onClick={onContact}>
          Contact
        </button>
        <a
          className="profile-button"
          href="/#about"
          onClick={(event) => handleLink(event, "/#about")}
        >
          Profile <ArrowRight aria-hidden="true" size={17} weight="bold" />
        </a>
      </div>

      <button
        aria-expanded={menuOpen}
        aria-label={menuOpen ? "Close menu" : "Open menu"}
        className="menu-button"
        onClick={() => setMenuOpen((current) => !current)}
      >
        {menuOpen ? <X size={23} /> : <List size={25} />}
        <span>{menuOpen ? "Close" : "Menu"}</span>
      </button>

      {menuOpen ? (
        <div className="mobile-menu">
          <nav aria-label="Mobile navigation">
            {navItems.map((item, index) => (
              <a
                href={item.href}
                key={item.label}
                onClick={(event) => handleLink(event, item.href)}
              >
                <span>0{index + 1}</span>
                {item.label}
                <ArrowRight aria-hidden="true" size={20} />
              </a>
            ))}
          </nav>
          <button
            className="mobile-contact"
            onClick={() => {
              setMenuOpen(false);
              onContact();
            }}
          >
            Contact
          </button>
        </div>
      ) : null}
    </header>
  );
}
