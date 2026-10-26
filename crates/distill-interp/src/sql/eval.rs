//! Small abstract domain for typed constants and SQL three-valued truth.
//! Unknown analysis is a set of possibilities, never the SQL NULL value.
use distill_core::{AnalysisBudget, DatabaseScope};
use sqlparser::ast::{BinaryOperator as B, Expr, UnaryOperator as U, Value};

const T: u8 = 1;
const F: u8 = 2;
const N: u8 = 4;
const ANY: u8 = T | F | N;
#[derive(Clone, Copy, Debug)]
enum Scalar {
    Int(i32),
    Bool(bool),
    Null,
    Unknown,
}

fn scalar(expr: &Expr, budget: &AnalysisBudget, depth: usize) -> Scalar {
    if depth > 48 || !budget.visit_node() {
        return Scalar::Unknown;
    }
    match expr {
        Expr::Value(v) => match &v.value {
            Value::Number(n, false) => n.parse::<i32>().map(Scalar::Int).unwrap_or(Scalar::Unknown),
            Value::Boolean(b) => Scalar::Bool(*b),
            Value::Null => Scalar::Null,
            _ => Scalar::Unknown,
        },
        Expr::Nested(e) => scalar(e, budget, depth + 1),
        Expr::UnaryOp { op, expr } => match (op, scalar(expr, budget, depth + 1)) {
            (U::Plus, v @ Scalar::Int(_)) => v,
            (U::Minus, Scalar::Int(n)) => {
                n.checked_neg().map(Scalar::Int).unwrap_or(Scalar::Unknown)
            }
            (U::Plus | U::Minus, Scalar::Null) => Scalar::Null,
            _ => Scalar::Unknown,
        },
        Expr::BinaryOp { left, op, right } => {
            match (
                scalar(left, budget, depth + 1),
                scalar(right, budget, depth + 1),
            ) {
                (Scalar::Int(a), Scalar::Int(b)) => match op {
                    B::Plus => a.checked_add(b),
                    B::Minus => a.checked_sub(b),
                    B::Multiply => a.checked_mul(b),
                    B::Divide => a.checked_div(b),
                    B::Modulo => a.checked_rem(b),
                    _ => None,
                }
                .map(Scalar::Int)
                .unwrap_or(Scalar::Unknown),
                _ => Scalar::Unknown,
            }
        }
        _ => Scalar::Unknown,
    }
}

fn combine(a: u8, b: u8, op: &B) -> u8 {
    let mut result = 0;
    for x in [T, F, N].into_iter().filter(|x| a & x != 0) {
        for y in [T, F, N].into_iter().filter(|y| b & y != 0) {
            result |= match op {
                B::And => {
                    if x == F || y == F {
                        F
                    } else if x == N || y == N {
                        N
                    } else {
                        T
                    }
                }
                B::Or => {
                    if x == T || y == T {
                        T
                    } else if x == N || y == N {
                        N
                    } else {
                        F
                    }
                }
                _ => ANY,
            };
        }
    }
    result
}
fn negate(a: u8) -> u8 {
    (if a & T != 0 { F } else { 0 }) | (if a & F != 0 { T } else { 0 }) | (a & N)
}

fn truth(expr: &Expr, budget: &AnalysisBudget, depth: usize) -> u8 {
    if depth > 48 || !budget.visit_node() {
        return ANY;
    }
    match expr {
        Expr::Nested(e) => truth(e, budget, depth + 1),
        Expr::UnaryOp { op: U::Not, expr } => negate(truth(expr, budget, depth + 1)),
        Expr::BinaryOp {
            left,
            op: op @ (B::And | B::Or),
            right,
        } => combine(
            truth(left, budget, depth + 1),
            truth(right, budget, depth + 1),
            op,
        ),
        Expr::BinaryOp {
            left,
            op: op @ (B::Eq | B::NotEq | B::Lt | B::LtEq | B::Gt | B::GtEq),
            right,
        } => {
            let a = scalar(left, budget, depth + 1);
            let b = scalar(right, budget, depth + 1);
            let ordering = match (a, b) {
                (Scalar::Int(a), Scalar::Int(b)) => Some(a.cmp(&b)),
                (Scalar::Bool(a), Scalar::Bool(b)) if matches!(op, B::Eq | B::NotEq) => {
                    Some(a.cmp(&b))
                }
                (Scalar::Unknown, _) | (_, Scalar::Unknown) => None,
                (Scalar::Null, _) | (_, Scalar::Null) => return N,
                _ => None,
            };
            match ordering {
                Some(order) => {
                    if match op {
                        B::Eq => order.is_eq(),
                        B::NotEq => !order.is_eq(),
                        B::Lt => order.is_lt(),
                        B::LtEq => !order.is_gt(),
                        B::Gt => order.is_gt(),
                        B::GtEq => !order.is_lt(),
                        _ => false,
                    } {
                        T
                    } else {
                        F
                    }
                }
                None => ANY,
            }
        }
        Expr::IsTrue(e)
        | Expr::IsNotTrue(e)
        | Expr::IsFalse(e)
        | Expr::IsNotFalse(e)
        | Expr::IsUnknown(e)
        | Expr::IsNotUnknown(e) => {
            let a = truth(e, budget, depth + 1);
            let wanted = match expr {
                Expr::IsTrue(_) | Expr::IsNotTrue(_) => T,
                Expr::IsFalse(_) | Expr::IsNotFalse(_) => F,
                _ => N,
            };
            let result =
                (if a & wanted != 0 { T } else { 0 }) | (if a & !wanted != 0 { F } else { 0 });
            if matches!(
                expr,
                Expr::IsNotTrue(_) | Expr::IsNotFalse(_) | Expr::IsNotUnknown(_)
            ) {
                negate(result)
            } else {
                result
            }
        }
        Expr::IsNull(e) | Expr::IsNotNull(e) => {
            let a = match scalar(e, budget, depth + 1) {
                Scalar::Null => T,
                Scalar::Unknown => T | F,
                _ => F,
            };
            if matches!(expr, Expr::IsNotNull(_)) {
                negate(a)
            } else {
                a
            }
        }
        _ => match scalar(expr, budget, depth + 1) {
            Scalar::Bool(true) => T,
            Scalar::Bool(false) => F,
            Scalar::Null => N,
            _ => ANY,
        },
    }
}

fn row_condition(expr: &Expr, depth: usize) -> bool {
    if depth > 48 {
        return false;
    }
    match expr {
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => true,
        Expr::Nested(e)
        | Expr::IsNull(e)
        | Expr::IsNotNull(e)
        | Expr::IsTrue(e)
        | Expr::IsFalse(e) => row_condition(e, depth + 1),
        Expr::UnaryOp { op: U::Not, expr } => row_condition(expr, depth + 1),
        Expr::BinaryOp {
            left,
            right,
            op: B::Eq | B::NotEq | B::Lt | B::LtEq | B::Gt | B::GtEq | B::And | B::Or,
        } => row_condition(left, depth + 1) || row_condition(right, depth + 1),
        _ => false,
    }
}

pub(super) fn scope(expr: Option<&Expr>, budget: &AnalysisBudget) -> DatabaseScope {
    let Some(expr) = expr else {
        return DatabaseScope::AllRows;
    };
    let values = truth(expr, budget, 0);
    if values == T {
        DatabaseScope::AllRows
    } else if values & T == 0 {
        DatabaseScope::NoRows
    } else if row_condition(expr, 0) {
        DatabaseScope::ConditionalRows
    } else {
        DatabaseScope::Unresolved
    }
}

pub(super) fn option_bool(expr: &Expr, budget: &AnalysisBudget) -> Option<bool> {
    match expr {
        Expr::Identifier(i) if i.quote_style.is_none() && i.value.eq_ignore_ascii_case("off") => {
            Some(false)
        }
        Expr::Identifier(i) if i.quote_style.is_none() && i.value.eq_ignore_ascii_case("on") => {
            Some(true)
        }
        Expr::Value(v) if matches!(&v.value, Value::SingleQuotedString(_)) => {
            let Value::SingleQuotedString(s) = &v.value else {
                unreachable!()
            };
            match s.to_ascii_lowercase().as_str() {
                "true" | "on" | "1" => Some(true),
                "false" | "off" | "0" => Some(false),
                _ => None,
            }
        }
        _ => match scalar(expr, budget, 0) {
            Scalar::Bool(b) => Some(b),
            Scalar::Int(0) => Some(false),
            Scalar::Int(1) => Some(true),
            _ => None,
        },
    }
}
