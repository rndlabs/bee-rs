use std::sync::Arc;
use std::cell::Cell;
use web_sys::{Url, HtmlInputElement};
use serde::{Serialize, Deserialize};
use futures_signals::signal::{Signal, SignalExt, Mutable};
use futures_signals::signal_vec::{SignalVec, SignalVecExt, MutableVec};
use dominator::{Dom, EventOptions, text_signal, html, clone, events, link, with_node, routing};

use crate::util::{trim, local_storage};

// use crate::todo::Todo;
// use crate::util::{trim, local_storage};

// Would do some route stuff here if we had more than one page
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Home,
}

impl Route {
    pub fn from_url(url: &str) -> Self {
        let url = Url::new(&url).unwrap();
        match url.hash().as_str() {
            "#/" => Self::Home,
            _ => Self::Home,
        }
    }

    pub fn to_url(self) -> String {
        match self {
            Route::Home => "#/".to_owned(),
        }
    }
}

impl Default for Route {
    fn default() -> Self {
        Self::from_url(&routing::url().lock_ref())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct App {
    // the private key
    pub private_key: Mutable<String>,
    // the batch id
    pub batch_id: Mutable<String>,
    // the bucket id
    pub bucket_id: Mutable<u32>,
    // the chunk position in the bucket
    pub bucket_depth_position: Mutable<u32>,
    // the data
    pub data: Mutable<String>,

    #[serde(skip)]
    route: Mutable<Route>,
}

impl App {
    pub fn new() -> Arc<Self> {
        Arc::new(App {
            private_key: Mutable::new("".to_owned()),
            batch_id: Mutable::new("".to_owned()),
            bucket_id: Mutable::new(0),
            bucket_depth_position: Mutable::new(0),
            data: Mutable::new("".to_owned()),
            route: Mutable::new(Route::default()),
        })
    }

    pub fn deserialize() -> Arc<Self> {
        local_storage()
            .get_item("bee-rs-wasm-playground")
            .unwrap()
            .and_then(|state_json| {
                serde_json::from_str::<App>(&state_json).ok()
            })
            .map(Arc::new)
            .unwrap_or_else(|| Self::new())
    }

    pub fn serialize(&self) {
        let state_json = serde_json::to_string(self).unwrap();

        local_storage()
            .set_item("bee-rs-wasm-playground", state_json.as_str())
            .unwrap();
    }

    pub fn route(&self) -> impl Signal<Item = Route> {
        self.route.signal()
    }

    fn render_header(app: Arc<Self>) -> Dom {
        html!("header", {
            .class("header")
            .children(&mut [
                html!("h1", {
                    .text("bee-rs Wasm Playground")
                }),


            ])
        })
    }

    fn render_main(app: Arc<Self>) -> Dom {
        html!("section", {
            .class("main")

            .children(&mut [
                html!("div", {
                    .class("row")
                    .children(&mut [
                        html!("label", { .text("Private Key:") }),
                        html!("input" => HtmlInputElement, {
                            .attr("type", "text")
                            .prop_signal("value", app.private_key.signal_cloned())
                        }),
                    ])
                }),
                html!("div", {
                    .class("row")
                    .children(&mut [
                        html!("label", { .text("Batch ID:") }),
                        html!("input" => HtmlInputElement, {
                            .attr("type", "text")
                            .prop_signal("value", app.batch_id.signal_cloned())
                        }),
                    ])
                }),
                html!("div", {
                    .class("row")
                    .children(&mut [
                        html!("label", { .text("Bucket ID:") }),
                        html!("input" => HtmlInputElement, {
                            .attr("type", "number")
                            .prop_signal("value", app.bucket_id.signal_cloned())
                        }),
                        html!("label", { .text("Bucket Depth Position:") }),
                        html!("input" => HtmlInputElement, {
                            .attr("type", "number")
                            .prop_signal("value", app.bucket_depth_position.signal_cloned())
                        }),
                    ])
                }),
                html!("div", {
                    .class("row")
                    .children(&mut [
                        html!("label", { .text("Data:") }),
                        html!("textarea", {
                            .attr("rows", "10")
                            .attr("cols", "80")
                            .prop_signal("value", app.data.signal_cloned())
                        }),
                    ])
                }),
                html!("div", {
                    .class("row")
                    .children(&mut [
                        html!("button", {
                            .text("Calculate")
                            .event(clone!(app => move |_: events::Click| {
                                todo!();
                                // app.serialize();
                            }))
                        }),
                    ])
                }),
                // show output
                html!("div", {
                    .class("row")
                    .children(&mut [
                        html!("label", { .text("Output:") }),
                        html!("textarea", {
                            .attr("rows", "10")
                            .attr("cols", "80")
                            .prop_signal("value", app.data.signal_cloned())
                        }),
                    ])
                })
            ])
        })
    }

    pub fn render(app: Arc<Self>) -> Dom {
        html!("section", {
            .class("playground")

            // Update the Route when the URL changes
            .future(routing::url()
                .signal_ref(|url| Route::from_url(url))
                .for_each(clone!(app => move |route| {
                    app.route.set_neq(route);
                    async {}
                })))

            .children(&mut [
                Self::render_header(app.clone()),
                Self::render_main(app.clone()),
                // Self::render_footer(app.clone()),
            ])
        })
    }
}