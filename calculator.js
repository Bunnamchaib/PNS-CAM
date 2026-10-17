'use strict';

// A basic immediate-execution calculator. No eval or generated JavaScript.
class Calculator {
  constructor() { this.reset(); }

  reset() {
    this.input = '0';
    this.total = null;
    this.operator = null;
    this.fresh = true;
    this.expression = '';
    this.trace = '';
  }

  format(value) {
    return Number.isFinite(value) ? String(Number(value.toPrecision(12))) : 'Error';
  }

  calculate(a, op, b) {
    if (op === '+') return a + b;
    if (op === '-') return a - b;
    if (op === '*') return a * b;
    return b === 0 ? NaN : a / b;
  }

  press(key) {
    let unlock = false;
    if (!/^(?:[0-9.+*/=\-%]|C|sign)$/.test(key)) return this.view(false);
    if (key === 'C') { this.reset(); return this.view(false); }
    if (this.input === 'Error') this.reset();
    this.trace = (this.trace + key).slice(-64);

    if (/^[0-9.]$/.test(key)) {
      if (this.fresh) {
        if (!this.operator) this.expression = '';
        this.input = key === '.' ? '0.' : key;
        this.fresh = false;
      } else if (key === '.') {
        if (!this.input.includes('.')) this.input += '.';
      } else if (this.input.length < 14) {
        this.input = this.input === '0' ? key : this.input + key;
      }
    } else if (key === 'sign' || key === '%') {
      this.input = this.format(key === 'sign' ? -Number(this.input) : Number(this.input) / 100);
    } else if (key === '=') {
      unlock = this.trace === '1+1=';
      if (this.operator && !this.fresh) {
        this.expression = `${this.format(this.total)} ${this.operator} ${this.input} =`;
        this.input = this.format(this.calculate(this.total, this.operator, Number(this.input)));
      }
      this.total = null;
      this.operator = null;
      this.fresh = true;
      this.trace = '';
    } else {
      if (this.operator && !this.fresh) {
        this.input = this.format(this.calculate(this.total, this.operator, Number(this.input)));
      }
      if (this.input === 'Error') {
        this.operator = null;
        this.total = null;
      } else {
        this.total = Number(this.input);
        this.operator = key;
        this.expression = `${this.input} ${key}`;
      }
      this.fresh = true;
    }
    return this.view(unlock);
  }

  view(unlock) {
    return { display: this.input, expression: this.expression, unlock };
  }
}

if (typeof module !== 'undefined' && module.exports) module.exports = { Calculator };
