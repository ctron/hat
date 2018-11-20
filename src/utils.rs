/*******************************************************************************
 * Copyright (c) 2018 Red Hat Inc
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/

pub trait Either {
    fn either<T>(&self, this:T, that:T) -> T;
}

impl Either for bool {
    fn either<T>(&self, this:T, that:T) -> T  {
        if *self { this } else { that }
    }
}
